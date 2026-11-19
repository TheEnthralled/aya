use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{
    Error, FnArg, Ident, ImplItem, ImplItemConst, ImplItemFn, ItemImpl, Path, Result, ReturnType,
    Type, ext::IdentExt as _, spanned::Spanned as _,
};

use crate::args::Args;

pub(crate) struct StructOps {
    item: ItemImpl,
    name: Option<String>,
    plain: bool,
    optional: bool,
}

/// A function in the `impl` block: one function pointer member of the struct.
struct Member<'a> {
    item: &'a ImplItemFn,
    name: &'a Ident,
    arg_types: Vec<&'a Type>,
    sleepable: bool,
}

impl StructOps {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let name = args.pop_string("name");
        let plain = args.pop_bool("plain");
        let optional = args.pop_bool("optional");
        args.into_error()?;
        Ok(Self {
            item,
            name,
            plain,
            optional,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let Self {
            item,
            name,
            plain,
            optional,
        } = self;
        let ItemImpl {
            attrs: _,
            modifiers: _,
            unsafety: _,
            impl_token,
            generics,
            trait_,
            self_ty,
            brace_token: _,
            items,
        } = item;

        if !generics.params.is_empty() {
            return Err(Error::new(
                generics.span(),
                "a struct_ops implementation cannot be generic",
            ));
        }
        // `impl Qdisc_ops for Fifo`: the kernel struct sits where a trait would.
        let Some((struct_path, _for)) = trait_ else {
            return Err(Error::new(
                impl_token.span(),
                "expected `impl <kernel struct> for <type>`",
            ));
        };
        let struct_ident = &last_segment(struct_path)?.ident;
        let instance_name = if let Some(name) = name {
            name.clone()
        } else {
            let Type::Path(self_path) = &**self_ty else {
                return Err(Error::new(
                    self_ty.span(),
                    "name the instance with `name = \"...\"`",
                ));
            };
            snake_case(&last_segment(&self_path.path)?.ident.unraw().to_string())
        };
        let instance_ident = Ident::new(&instance_name, Span::call_site());

        let mut consts = Vec::new();
        let mut members = Vec::new();
        for item in items {
            match item {
                ImplItem::Const(item) => consts.push(item),
                ImplItem::Fn(item) => members.push(Member::parse(item)?),
                item => {
                    return Err(Error::new(
                        item.span(),
                        "only functions and constants can be members of a struct_ops instance",
                    ));
                }
            }
        }

        // The user's items, as inherent items of the type. The functions get
        // the calling convention of the kernel's function pointers.
        let inherent_consts = consts.iter().map(|item| {
            quote! {
                #[allow(non_upper_case_globals)]
                #item
            }
        });
        let inherent_fns = members.iter().map(|member| {
            let ImplItemFn {
                attrs,
                vis,
                modifiers: _,
                sig,
                block,
            } = member.item;
            let attrs = attrs
                .iter()
                .filter(|attr| !attr.path().is_ident("sleepable"));
            let name = member.name;
            let inputs = &sig.inputs;
            let output = &sig.output;
            quote! {
                #(#attrs)*
                #[inline(always)]
                #vis unsafe extern "C" fn #name(#inputs) #output #block
            }
        });

        // Assigning each item to the kernel struct's member of the same name
        // checks its type against the kernel bindings. The assignments carry
        // the item's span, so that a mismatch is reported at the item.
        let checked_fns = members.iter().map(|member| {
            let name = member.name;
            quote_spanned! {name.span()=>
                ops.#name = ::core::option::Option::Some(<#self_ty>::#name);
            }
        });
        let checked_consts = consts.iter().map(|item| {
            let name = &item.ident;
            quote_spanned! {name.span()=>
                ops.#name = <#self_ty>::#name;
            }
        });

        // One program per function. A program is entered with a pointer to
        // its arguments.
        let programs = members.iter().map(|member| {
            let name = member.name;
            let program = member.program(&instance_name);
            let section = format!(
                "{}/{program}",
                if member.sleepable {
                    "struct_ops.s"
                } else {
                    "struct_ops"
                }
            );
            let output = &member.item.sig.output;
            let args = (0..member.arg_types.len()).map(|n| quote!(ctx.arg(#n)));
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = #section)]
                #[allow(unused_variables)]
                unsafe extern "C" fn #program(ctx: *mut ::core::ffi::c_void) #output {
                    let ctx = ::aya_ebpf::programs::StructOpsContext::new(ctx);
                    unsafe { <#self_ty>::#name(#(#args),*) }
                }
            }
        });

        // The instance: a struct named like the kernel's, holding only the
        // members this block defines, in a `.struct_ops` section.
        let fields = items.iter().filter_map(|item| match item {
            ImplItem::Const(ImplItemConst { ident, ty, .. }) => Some(quote!(#ident: #ty)),
            ImplItem::Fn(item) => {
                let member = members
                    .iter()
                    .find(|member| ::core::ptr::eq(member.item, item))?;
                let name = member.name;
                let ty = member.fn_ptr_type();
                Some(quote!(#name: #ty))
            }
            _ => None,
        });
        let values = items.iter().filter_map(|item| match item {
            ImplItem::Const(ImplItemConst { ident, .. }) => {
                Some(quote!(#ident: <#self_ty>::#ident))
            }
            ImplItem::Fn(item) => {
                let member = members
                    .iter()
                    .find(|member| ::core::ptr::eq(member.item, item))?;
                let name = member.name;
                let program = member.program(&instance_name);
                let output = &member.item.sig.output;
                let ty = member.fn_ptr_type();
                Some(quote! {
                    #name: unsafe {
                        ::core::mem::transmute::<
                            unsafe extern "C" fn(*mut ::core::ffi::c_void) #output,
                            #ty,
                        >(#program)
                    }
                })
            }
            _ => None,
        });
        let section = format!(
            "{}{}",
            if *optional { "?" } else { "" },
            if *plain {
                ".struct_ops"
            } else {
                ".struct_ops.link"
            }
        );

        Ok(quote! {
            impl #self_ty {
                #(#inherent_consts)*
                #(#inherent_fns)*
            }

            const _: fn(&mut #struct_path) = |ops| {
                #(#checked_fns)*
                #(#checked_consts)*
            };

            #(#programs)*

            const _: () = {
                #[repr(C)]
                #[allow(non_camel_case_types, non_upper_case_globals)]
                struct #struct_ident {
                    #(#fields,)*
                }

                // The instance is never written to.
                unsafe impl ::core::marker::Sync for #struct_ident {}

                #[unsafe(no_mangle)]
                #[unsafe(link_section = #section)]
                #[allow(non_upper_case_globals)]
                static #instance_ident: #struct_ident = #struct_ident {
                    #(#values,)*
                };
            };
        })
    }
}

impl<'a> Member<'a> {
    fn parse(item: &'a ImplItemFn) -> Result<Self> {
        let sig = &item.sig;
        if !sig.generics.params.is_empty() {
            return Err(Error::new(
                sig.generics.span(),
                "a struct_ops program cannot be generic",
            ));
        }
        let arg_types = sig
            .inputs
            .iter()
            .map(|arg| match arg {
                FnArg::Typed(arg) => Ok(&*arg.ty),
                FnArg::Receiver(receiver) => Err(Error::new(
                    receiver.span(),
                    "a struct_ops program cannot take `self`",
                )),
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            item,
            name: &sig.ident,
            arg_types,
            sleepable: item
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("sleepable")),
        })
    }

    /// The program's name: `<instance>_<member>`.
    fn program(&self, instance_name: &str) -> Ident {
        format_ident!("{}_{}", instance_name, self.name.unraw())
    }

    /// The type of the kernel's function pointer for this member.
    fn fn_ptr_type(&self) -> TokenStream {
        let arg_types = &self.arg_types;
        let output: &ReturnType = &self.item.sig.output;
        quote!(unsafe extern "C" fn(#(#arg_types),*) #output)
    }
}

fn last_segment(path: &Path) -> Result<&syn::PathSegment> {
    path.segments
        .last()
        .ok_or_else(|| Error::new(path.span(), "expected a path"))
}

/// `RawFifo` -> `raw_fifo`.
fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i != 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    fn expand(attrs: TokenStream, item: TokenStream) -> Result<String> {
        StructOps::parse(attrs, item)?
            .expand()
            .map(|expanded| expanded.to_string())
    }

    #[test]
    fn test_struct_ops() {
        let expanded = expand(
            parse_quote!(),
            parse_quote!(
                impl Qdisc_ops for Fifo {
                    const id: [c_char; 16] = ID;

                    fn enqueue(skb: *mut sk_buff, sch: *mut Qdisc) -> c_int {
                        0
                    }

                    #[sleepable]
                    fn reset(sch: *mut Qdisc) {}
                }
            ),
        )
        .unwrap();
        let expected = quote! {
            impl Fifo {
                #[allow(non_upper_case_globals)]
                const id: [c_char; 16] = ID;
                #[inline(always)]
                unsafe extern "C" fn enqueue(skb: *mut sk_buff, sch: *mut Qdisc) -> c_int {
                    0
                }
                #[inline(always)]
                unsafe extern "C" fn reset(sch: *mut Qdisc) {}
            }

            const _: fn(&mut Qdisc_ops) = |ops| {
                ops.enqueue = ::core::option::Option::Some(<Fifo>::enqueue);
                ops.reset = ::core::option::Option::Some(<Fifo>::reset);
                ops.id = <Fifo>::id;
            };

            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops/fifo_enqueue")]
            #[allow(unused_variables)]
            unsafe extern "C" fn fifo_enqueue(ctx: *mut ::core::ffi::c_void) -> c_int {
                let ctx = ::aya_ebpf::programs::StructOpsContext::new(ctx);
                unsafe { <Fifo>::enqueue(ctx.arg(0usize), ctx.arg(1usize)) }
            }

            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops.s/fifo_reset")]
            #[allow(unused_variables)]
            unsafe extern "C" fn fifo_reset(ctx: *mut ::core::ffi::c_void) {
                let ctx = ::aya_ebpf::programs::StructOpsContext::new(ctx);
                unsafe { <Fifo>::reset(ctx.arg(0usize)) }
            }

            const _: () = {
                #[repr(C)]
                #[allow(non_camel_case_types, non_upper_case_globals)]
                struct Qdisc_ops {
                    id: [c_char; 16],
                    enqueue: unsafe extern "C" fn(*mut sk_buff, *mut Qdisc) -> c_int,
                    reset: unsafe extern "C" fn(*mut Qdisc),
                }

                unsafe impl ::core::marker::Sync for Qdisc_ops {}

                #[unsafe(no_mangle)]
                #[unsafe(link_section = ".struct_ops.link")]
                #[allow(non_upper_case_globals)]
                static fifo: Qdisc_ops = Qdisc_ops {
                    id: <Fifo>::id,
                    enqueue: unsafe {
                        ::core::mem::transmute::<
                            unsafe extern "C" fn(*mut ::core::ffi::c_void) -> c_int,
                            unsafe extern "C" fn(*mut sk_buff, *mut Qdisc) -> c_int,
                        >(fifo_enqueue)
                    },
                    reset: unsafe {
                        ::core::mem::transmute::<
                            unsafe extern "C" fn(*mut ::core::ffi::c_void),
                            unsafe extern "C" fn(*mut Qdisc),
                        >(fifo_reset)
                    },
                };
            };
        };
        assert_eq!(expected.to_string(), expanded);
    }

    #[test]
    fn test_struct_ops_args() {
        let item = || -> TokenStream {
            parse_quote!(
                impl vmlinux::Qdisc_ops for RawFifo {
                    fn r#yield() {}
                }
            )
        };

        // The kernel struct may be a path, the instance is named after the
        // type, and a raw identifier names the member without its `r#`.
        let expanded = expand(parse_quote!(), item()).unwrap();
        assert!(expanded.contains(r#"link_section = ".struct_ops.link""#));
        assert!(expanded.contains("static raw_fifo : Qdisc_ops"));
        assert!(expanded.contains(r#"link_section = "struct_ops/raw_fifo_yield""#));
        assert!(expanded.contains("const _ : fn (& mut vmlinux :: Qdisc_ops)"));

        let expanded = expand(parse_quote!(plain, optional, name = "fq"), item()).unwrap();
        assert!(expanded.contains(r#"link_section = "?.struct_ops""#));
        assert!(expanded.contains("static fq : Qdisc_ops"));
        assert!(expanded.contains(r#"link_section = "struct_ops/fq_yield""#));
    }

    #[test]
    fn test_struct_ops_invalid() {
        let error =
            |attrs: TokenStream, item: TokenStream| expand(attrs, item).unwrap_err().to_string();

        assert_eq!(
            error(parse_quote!(), parse_quote!(impl Fifo {})),
            "expected `impl <kernel struct> for <type>`"
        );
        assert_eq!(
            error(
                parse_quote!(),
                parse_quote!(
                    impl<T> Qdisc_ops for Fifo<T> {}
                )
            ),
            "a struct_ops implementation cannot be generic"
        );
        assert_eq!(
            error(
                parse_quote!(),
                parse_quote!(
                    impl Qdisc_ops for Fifo {
                        fn reset(&self) {}
                    }
                )
            ),
            "a struct_ops program cannot take `self`"
        );
        assert_eq!(
            error(
                parse_quote!(),
                parse_quote!(
                    impl Qdisc_ops for Fifo {
                        type Queue = u32;
                    }
                )
            ),
            "only functions and constants can be members of a struct_ops instance"
        );
        assert_eq!(
            error(parse_quote!(link), parse_quote!(impl Qdisc_ops for Fifo {})),
            "invalid argument"
        );
    }
}
