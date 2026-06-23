//! Procedural macros for Outbe precompile contracts and storage DSL.

mod dispatch_codegen;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Data, DeriveInput, Expr, Fields, GenericArgument, Ident, LitBool, LitInt, PathArguments, Token,
    Type,
};

struct ContractConfig {
    address: Option<Expr>,
}

impl Parse for ContractConfig {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self { address: None });
        }
        let ident: Ident = input.parse()?;
        if ident != "addr" && ident != "address" {
            return Err(syn::Error::new(ident.span(), "expected `addr = EXPR`"));
        }
        input.parse::<Token![=]>()?;
        let address: Expr = input.parse()?;
        Ok(Self {
            address: Some(address),
        })
    }
}

#[derive(Default, Clone)]
struct CommonFieldAttrs {
    explicit_slot: Option<u64>,
    order: Option<u64>,
    default: Option<Expr>,
    deprecated: bool,
    key: bool,
}

fn parse_common_field_attrs(attrs: &[syn::Attribute]) -> syn::Result<CommonFieldAttrs> {
    let mut out = CommonFieldAttrs::default();
    for attr in attrs {
        if attr.path().is_ident("slot") {
            let lit: LitInt = attr.parse_args()?;
            out.explicit_slot = Some(lit.base10_parse()?);
            continue;
        }
        if attr.path().is_ident("key") {
            out.key = true;
            continue;
        }
        if attr.path().is_ident("attribute") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("order") {
                    let lit: LitInt = meta.value()?.parse()?;
                    out.order = Some(lit.base10_parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("default") {
                    out.default = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("deprecated") {
                    let lit: LitBool = meta.value()?.parse()?;
                    out.deprecated = lit.value;
                    return Ok(());
                }
                Err(meta.error("unsupported key in #[attribute(...)]"))
            })?;
        }
    }
    Ok(out)
}

#[derive(Clone)]
struct ContractFieldInfo {
    vis: syn::Visibility,
    name: Ident,
    ty: Type,
    attrs: CommonFieldAttrs,
}

#[derive(Default)]
struct StorageRecordConfig {
    exists_field: Option<Ident>,
}

impl Parse for StorageRecordConfig {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut config = Self::default();
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            if ident != "exists_field" {
                return Err(syn::Error::new(
                    ident.span(),
                    "expected `exists_field = ident`",
                ));
            }
            input.parse::<Token![=]>()?;
            config.exists_field = Some(input.parse()?);
            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }
        Ok(config)
    }
}

#[derive(Clone)]
struct RecordFieldInfo {
    vis: syn::Visibility,
    name: Ident,
    ty: Type,
    attrs: CommonFieldAttrs,
}

fn type_args(ty: &Type) -> Option<Vec<GenericArgument>> {
    let Type::Path(p) = ty else {
        return None;
    };
    let seg = p.path.segments.last()?;
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Some(Vec::new());
    };
    Some(args.args.iter().cloned().collect())
}

fn last_type_ident(ty: &Type) -> Option<String> {
    let Type::Path(p) = ty else {
        return None;
    };
    Some(p.path.segments.last()?.ident.to_string())
}

fn is_ident_type(ty: &Type, wanted: &[&str]) -> bool {
    last_type_ident(ty)
        .map(|name| wanted.iter().any(|wanted| name == *wanted))
        .unwrap_or(false)
}

fn is_mapping_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Mapping"])
}

fn is_slot_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Slot"])
}

fn is_storage_collection(ty: &Type) -> Option<(&'static str, u64)> {
    if let Some(name) = last_type_ident(ty) {
        return match name.as_str() {
            "StorageVec" => Some(("StorageVec", 1)),
            "StorageSet" => Some(("StorageSet", 2)),
            "StorageArray" => Some(("StorageArray", 1)),
            "StorageBytes" => Some(("StorageBytes", 1)),
            _ => None,
        };
    }
    None
}

fn is_dsl_value_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Value"])
}

fn is_dsl_map_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Map"])
}

fn is_dsl_list_type(ty: &Type) -> bool {
    is_ident_type(ty, &["List"])
}

fn is_dsl_set_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Set"])
}

fn is_dsl_binary_heap_type(ty: &Type) -> bool {
    is_ident_type(ty, &["BinaryHeap"])
}

fn is_dsl_deque_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Deque"])
}

fn is_dsl_circular_buffer_type(ty: &Type) -> bool {
    is_ident_type(ty, &["CircularBuffer"])
}

fn is_optional_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Optional", "Option"])
}

fn is_deprecated_type(ty: &Type) -> bool {
    is_ident_type(ty, &["Deprecated"])
}

fn unwrap_single_generic_type(ty: &Type) -> Option<Type> {
    let args = type_args(ty)?;
    match args.first() {
        Some(GenericArgument::Type(inner)) => Some(inner.clone()),
        _ => None,
    }
}

fn is_scalar_like_type(ty: &Type) -> bool {
    matches!(
        last_type_ident(ty).as_deref(),
        Some("u8")
            | Some("u32")
            | Some("u64")
            | Some("bool")
            | Some("U256")
            | Some("Address")
            | Some("B256")
            | Some("Optional")
            | Some("Option")
            | Some("Deprecated")
    )
}

fn storage_type_with_lifetime(ty: &Type) -> proc_macro2::TokenStream {
    let Type::Path(p) = ty else {
        return quote! { #ty };
    };
    let Some(seg) = p.path.segments.last() else {
        return quote! { #ty };
    };
    let name = &seg.ident;

    match name.to_string().as_str() {
        "Slot" => {
            let args = type_args(ty).unwrap_or_default();
            quote! { #name<'storage, #(#args),*> }
        }
        "Mapping" => {
            let args = type_args(ty).unwrap_or_default();
            if args.len() == 2 {
                let key = &args[0];
                let value = match &args[1] {
                    GenericArgument::Type(inner) => storage_type_with_lifetime(inner),
                    other => quote! { #other },
                };
                quote! { #name<'storage, #key, #value> }
            } else {
                quote! { #ty }
            }
        }
        "StorageBytes" => quote! { #name<'storage> },
        "StorageVec" | "StorageSet" | "StorageArray" => {
            let args = type_args(ty).unwrap_or_default();
            quote! { #name<'storage, #(#args),*> }
        }
        "Value" => {
            let inner = unwrap_single_generic_type(ty).unwrap();
            quote! { ::outbe_primitives::storage::dsl::Value<'storage, #inner> }
        }
        "Map" => {
            let args = type_args(ty).unwrap_or_default();
            if args.len() == 2 {
                let key = &args[0];
                let value = match &args[1] {
                    GenericArgument::Type(inner) => storage_type_with_lifetime(inner),
                    other => quote! { #other },
                };
                quote! { ::outbe_primitives::storage::dsl::Map<'storage, #key, #value> }
            } else {
                quote! { ::outbe_primitives::storage::dsl::Map<'storage, #(#args),*> }
            }
        }
        "List" => {
            let inner = unwrap_single_generic_type(ty).unwrap();
            quote! { ::outbe_primitives::storage::dsl::List<'storage, #inner> }
        }
        "Set" => {
            let inner = unwrap_single_generic_type(ty).unwrap();
            quote! { ::outbe_primitives::storage::dsl::Set<'storage, #inner> }
        }
        "BinaryHeap" => {
            let inner = unwrap_single_generic_type(ty).unwrap();
            quote! { ::outbe_primitives::storage::dsl::BinaryHeap<'storage, #inner> }
        }
        "Deque" => {
            let inner = unwrap_single_generic_type(ty).unwrap();
            quote! { ::outbe_primitives::storage::dsl::Deque<'storage, #inner> }
        }
        "CircularBuffer" => {
            let inner = unwrap_single_generic_type(ty).unwrap();
            quote! { ::outbe_primitives::storage::dsl::CircularBuffer<'storage, #inner> }
        }
        _ => quote! { #ty },
    }
}

fn contract_slot_count_expr(ty: &Type) -> proc_macro2::TokenStream {
    if is_slot_type(ty)
        || is_mapping_type(ty)
        || is_dsl_value_type(ty)
        || is_dsl_list_type(ty)
        || is_dsl_binary_heap_type(ty)
    {
        return quote! { 1u64 };
    }
    if is_dsl_set_type(ty) || is_dsl_deque_type(ty) || is_dsl_circular_buffer_type(ty) {
        return quote! { 2u64 };
    }
    if let Some((_, count)) = is_storage_collection(ty) {
        return quote! { #count as u64 };
    }
    if is_dsl_map_type(ty) {
        let args = type_args(ty).unwrap_or_default();
        if let Some(GenericArgument::Type(value_ty)) = args.get(1) {
            if is_scalar_like_type(value_ty) || is_dsl_list_type(value_ty) {
                quote! { 1u64 }
            } else {
                quote! { <#value_ty as ::outbe_primitives::storage::dsl::StorageRecord>::SLOTS as u64 }
            }
        } else {
            quote! { 1u64 }
        }
    } else {
        quote! { 1u64 }
    }
}

fn record_field_storage_slots(ty: &Type) -> syn::Result<u64> {
    if is_optional_type(ty) {
        return Ok(2);
    }
    if is_deprecated_type(ty) {
        let inner = unwrap_single_generic_type(ty)
            .ok_or_else(|| syn::Error::new(ty.span(), "Deprecated<T> requires one type arg"))?;
        return record_field_storage_slots(&inner);
    }
    Ok(1)
}

fn record_field_inner_storage_type(ty: &Type) -> Type {
    if is_optional_type(ty) || is_deprecated_type(ty) {
        return unwrap_single_generic_type(ty).unwrap_or_else(|| ty.clone());
    }
    ty.clone()
}

fn is_string_type(ty: &Type) -> bool {
    is_ident_type(ty, &["String"])
}

fn is_vec_u8_type(ty: &Type) -> bool {
    if last_type_ident(ty).as_deref() != Some("Vec") {
        return false;
    }
    let Some(args) = type_args(ty) else {
        return false;
    };
    matches!(args.first(), Some(GenericArgument::Type(inner)) if is_ident_type(inner, &["u8"]))
}

enum DynamicFieldKind {
    String,
    VecU8,
}

fn dynamic_field_kind(ty: &Type) -> Option<DynamicFieldKind> {
    let inner = record_field_inner_storage_type(ty);
    if is_string_type(&inner) {
        Some(DynamicFieldKind::String)
    } else if is_vec_u8_type(&inner) {
        Some(DynamicFieldKind::VecU8)
    } else {
        None
    }
}

fn dynamic_bytes_mapping_new(
    receiver: &Ident,
    key_ty: &Type,
    offset_lit: u64,
) -> proc_macro2::TokenStream {
    quote! {
        ::outbe_primitives::storage::types::Mapping::<#key_ty, ::outbe_primitives::storage::types::StorageBytes>::new(
            #receiver.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
            #receiver.address(),
            #receiver.storage(),
        )
    }
}

fn compute_order_based_offsets<T, FSlot, FOrder>(
    items: &[T],
    slot_count: FSlot,
    order: FOrder,
) -> syn::Result<Vec<u64>>
where
    FSlot: Fn(&T) -> syn::Result<u64>,
    FOrder: Fn(&T) -> Option<u64>,
{
    let mut indexed: Vec<(usize, u64, u64)> = items
        .iter()
        .enumerate()
        .map(|(i, item)| Ok((i, order(item).unwrap_or(i as u64), slot_count(item)?)))
        .collect::<syn::Result<_>>()?;

    indexed.sort_by_key(|(_, ord, _)| *ord);

    let mut offsets = vec![0u64; items.len()];
    let mut next = 0u64;
    for (idx, _, slots) in indexed {
        offsets[idx] = next;
        next += slots;
    }
    Ok(offsets)
}

#[proc_macro_attribute]
pub fn storage_schema(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Annotates an `impl` block whose methods (each carrying
/// `#[contract_public("sig")]`) declare a precompile's ABI surface and
/// dispatch wiring. Generates a private `sol!` interface plus a free
/// `pub fn dispatch(storage, data, caller, value) -> Result<Bytes>`.
///
/// Companion markers on individual methods:
/// - `#[contract_view]` — read-only; method takes only ABI args.
/// - `#[contract_payable]` — `caller: Address, value: U256` are the first
///   two parameters after `&mut self`, followed by ABI args.
/// - (no marker) — default mutating: `caller: Address` is the first
///   parameter after `&mut self`, followed by ABI args.
#[proc_macro_attribute]
pub fn contract_dispatch(attr: TokenStream, item: TokenStream) -> TokenStream {
    dispatch_codegen::expand_dispatch(attr, item)
}

/// Marks a method inside a `#[contract_dispatch]` impl block as an ABI
/// entry. The string is a Solidity-style signature; argument names are
/// taken from the Rust method (only types are read from the string).
/// Consumed by the surrounding `#[contract_dispatch]` macro.
#[proc_macro_attribute]
pub fn contract_public(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Inside a `#[contract_dispatch]` impl block: marks the method as
/// read-only (no caller / no msg.value injection). Consumed by the
/// surrounding `#[contract_dispatch]` macro.
#[proc_macro_attribute]
pub fn contract_view(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Inside a `#[contract_dispatch]` impl block: marks the method as
/// payable; first two parameters after `&mut self` are
/// `caller: Address, value: U256`. Consumed by the surrounding
/// `#[contract_dispatch]` macro.
#[proc_macro_attribute]
pub fn contract_payable(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let config = parse_macro_input!(attr as ContractConfig);
    let input = parse_macro_input!(item as DeriveInput);

    match generate_contract(input, config) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn generate_contract(
    input: DeriveInput,
    config: ContractConfig,
) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let vis = &input.vis;

    let named_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "only structs with named fields are supported",
                ))
            }
        },
        _ => return Err(syn::Error::new_spanned(name, "only structs are supported")),
    };

    let mut fields = Vec::new();
    for field in named_fields.iter() {
        let field_name = field.ident.as_ref().unwrap();
        let n = field_name.to_string();
        if n == "address" || n == "storage" {
            return Err(syn::Error::new_spanned(
                field_name,
                format!("field name `{n}` is reserved — generated automatically"),
            ));
        }
        fields.push(ContractFieldInfo {
            vis: field.vis.clone(),
            name: field_name.clone(),
            ty: field.ty.clone(),
            attrs: parse_common_field_attrs(&field.attrs)?,
        });
    }

    let use_order = fields.iter().any(|f| f.attrs.order.is_some())
        && fields.iter().all(|f| f.attrs.explicit_slot.is_none());

    let slot_assignments: Vec<proc_macro2::TokenStream> = if use_order {
        let mut ordered: Vec<(usize, u64, proc_macro2::TokenStream)> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                (
                    i,
                    f.attrs.order.unwrap_or(i as u64),
                    contract_slot_count_expr(&f.ty),
                )
            })
            .collect();
        ordered.sort_by_key(|(_, ord, _)| *ord);
        let mut slots = vec![quote! { 0u64 }; fields.len()];
        let mut next = quote! { 0u64 };
        for (idx, _, count) in ordered {
            slots[idx] = next.clone();
            next = quote! { (#next) + (#count) };
        }
        slots
    } else {
        let mut next_slot = quote! { 0u64 };
        let mut slots = Vec::with_capacity(fields.len());
        for f in &fields {
            if let Some(explicit) = f.attrs.explicit_slot {
                next_slot = quote! { #explicit as u64 };
            }
            slots.push(next_slot.clone());
            let count = contract_slot_count_expr(&f.ty);
            next_slot = quote! { (#next_slot) + (#count) };
        }
        slots
    };

    let field_decls: Vec<_> = fields
        .iter()
        .map(|f| {
            let v = &f.vis;
            let n = &f.name;
            let t = storage_type_with_lifetime(&f.ty);
            quote! { #v #n: #t }
        })
        .collect();

    let struct_def = quote! {
        #vis struct #name<'storage> {
            pub address: ::alloy_primitives::Address,
            pub storage: ::outbe_primitives::storage::StorageHandle<'storage>,
            #(#field_decls,)*
        }
    };

    let field_inits: Vec<_> = fields
        .iter()
        .zip(slot_assignments.iter())
        .map(|(f, slot)| {
            let n = &f.name;
            let ty = &f.ty;
            if is_mapping_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::Mapping::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_slot_type(ty) || is_dsl_value_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::Slot::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_dsl_map_type(ty) {
                quote! { #n: ::outbe_primitives::storage::dsl::Map::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_dsl_list_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::StorageVec::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_dsl_set_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::StorageSet::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_dsl_binary_heap_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::BinaryHeap::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_dsl_deque_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::StorageDeque::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if is_dsl_circular_buffer_type(ty) {
                quote! { #n: ::outbe_primitives::storage::types::StorageCircularBuffer::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else if let Some((coll_name, _)) = is_storage_collection(ty) {
                let coll_ident = syn::Ident::new(coll_name, proc_macro2::Span::call_site());
                quote! { #n: ::outbe_primitives::storage::types::#coll_ident::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            } else {
                quote! { #n: ::outbe_primitives::storage::types::Slot::new(::alloy_primitives::U256::from(#slot), address, storage.clone()) }
            }
        })
        .collect();

    let storage_backed_impl = if let Some(addr) = config.address.as_ref() {
        quote! {
            impl<'storage> ::outbe_primitives::storage::StorageBacked<'storage> for #name<'storage> {
                const DEFAULT_ADDRESS: ::alloy_primitives::Address = #addr;

                fn at(
                    storage: ::outbe_primitives::storage::StorageHandle<'storage>,
                    address: ::alloy_primitives::Address,
                ) -> Self {
                    #name::at(storage, address)
                }
            }
        }
    } else {
        quote! {}
    };

    let constructor = if let Some(addr) = config.address.as_ref() {
        quote! {
            impl<'storage> #name<'storage> {
                pub fn new(storage: impl ::core::convert::Into<::outbe_primitives::storage::StorageHandle<'storage>>) -> Self {
                    Self::at(storage, #addr)
                }

                pub fn at(
                    storage: impl ::core::convert::Into<::outbe_primitives::storage::StorageHandle<'storage>>,
                    address: ::alloy_primitives::Address,
                ) -> Self {
                    let storage = storage.into();
                    Self {
                        address,
                        storage: storage.clone(),
                        #(#field_inits,)*
                    }
                }

                pub fn emit<E: ::alloy_sol_types::SolEvent>(&mut self, event: E) -> ::outbe_primitives::error::Result<()> {
                    let log_data = event.encode_log_data();
                    self.storage.emit_event(self.address, log_data)
                }
            }
        }
    } else {
        quote! {
            impl<'storage> #name<'storage> {
                pub fn new(
                    storage: impl ::core::convert::Into<::outbe_primitives::storage::StorageHandle<'storage>>,
                    address: ::alloy_primitives::Address,
                ) -> Self {
                    let storage = storage.into();
                    Self {
                        address,
                        storage: storage.clone(),
                        #(#field_inits,)*
                    }
                }

                pub fn emit<E: ::alloy_sol_types::SolEvent>(&mut self, event: E) -> ::outbe_primitives::error::Result<()> {
                    let log_data = event.encode_log_data();
                    self.storage.emit_event(self.address, log_data)
                }
            }
        }
    };

    Ok(quote! {
        #struct_def
        #constructor
        #storage_backed_impl
    })
}

#[proc_macro_attribute]
pub fn storage_record(attr: TokenStream, item: TokenStream) -> TokenStream {
    let config = parse_macro_input!(attr as StorageRecordConfig);
    let input = parse_macro_input!(item as DeriveInput);

    match generate_storage_record(input, config) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn generate_storage_record(
    input: DeriveInput,
    config: StorageRecordConfig,
) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let vis = &input.vis;

    let named_fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "only structs with named fields are supported",
                ))
            }
        },
        _ => return Err(syn::Error::new_spanned(name, "only structs are supported")),
    };

    let mut fields = Vec::new();
    for field in named_fields.iter() {
        fields.push(RecordFieldInfo {
            vis: field.vis.clone(),
            name: field.ident.clone().unwrap(),
            ty: field.ty.clone(),
            attrs: parse_common_field_attrs(&field.attrs)?,
        });
    }

    let key_fields: Vec<_> = fields.iter().filter(|f| f.attrs.key).collect();
    if key_fields.len() != 1 {
        return Err(syn::Error::new_spanned(
            name,
            "#[storage_record] requires exactly one #[key] field",
        ));
    }
    let key_field = key_fields[0];
    let key_name = &key_field.name;
    let key_ty = &key_field.ty;

    let exists_field_ident = config.exists_field.ok_or_else(|| {
        syn::Error::new_spanned(
            name,
            "#[storage_record(...)] requires `exists_field = field_name`",
        )
    })?;

    let non_key_fields: Vec<_> = fields.iter().filter(|f| !f.attrs.key).cloned().collect();
    let non_key_offsets = compute_order_based_offsets(
        &non_key_fields,
        |f| record_field_storage_slots(&f.ty),
        |f| f.attrs.order,
    )?;
    let total_slots: u64 = non_key_fields
        .iter()
        .zip(non_key_offsets.iter())
        .map(|(f, offset)| offset + record_field_storage_slots(&f.ty).unwrap())
        .max()
        .unwrap_or(0);

    let struct_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let vis = &f.vis;
            let name = &f.name;
            let ty = &f.ty;
            quote! { #vis #name: #ty }
        })
        .collect();

    let cleaned_struct = quote! {
        #vis struct #name {
            #(#struct_fields,)*
        }
    };

    let with_key_defaults: Vec<_> = fields
        .iter()
        .map(|f| {
            let fname = &f.name;
            if f.attrs.key {
                quote! { #fname: key }
            } else if let Some(default) = &f.attrs.default {
                quote! { #fname: #default }
            } else {
                quote! { #fname: ::core::default::Default::default() }
            }
        })
        .collect();

    let helper_impl = quote! {
        impl #name {
            pub fn with_key(key: #key_ty) -> Self {
                Self {
                    #(#with_key_defaults,)*
                }
            }
        }
    };

    let entry_trait_name = format_ident!("{}EntryExt", name);
    let mut accessor_trait_methods = Vec::new();
    let mut accessor_impl_methods = Vec::new();
    let mut load_fields = Vec::new();
    let mut write_fields = Vec::new();
    let mut delete_fields = Vec::new();
    let mut exists_expr = None;

    for (field, offset) in non_key_fields.iter().zip(non_key_offsets.iter()) {
        let fname = &field.name;
        let storage_ty = record_field_inner_storage_type(&field.ty);
        let offset_lit = *offset;
        let dynamic_kind = dynamic_field_kind(&field.ty);

        if field.name == exists_field_ident && dynamic_kind.is_some() {
            return Err(syn::Error::new_spanned(
                &field.name,
                "exists_field cannot be a dynamic String or Vec<u8> record field",
            ));
        }
        if is_optional_type(&field.ty) && dynamic_kind.is_some() {
            return Err(syn::Error::new_spanned(
                &field.name,
                "optional dynamic String or Vec<u8> record fields are not supported",
            ));
        }

        // TODO: reduce boilerplate in constructors.
        let (mapping_read, mapping_write, mapping_delete) = match dynamic_kind {
            Some(DynamicFieldKind::String) => {
                let map_new =
                    dynamic_bytes_mapping_new(&format_ident!("entry"), key_ty, offset_lit);
                (
                    quote! { #map_new.read_string(entry.key_ref())? },
                    quote! { #map_new.write_string(entry.key_ref(), &value.#fname)?; },
                    quote! { #map_new.get_bytes(entry.key_ref()).clear()?; },
                )
            }
            Some(DynamicFieldKind::VecU8) => {
                let map_new =
                    dynamic_bytes_mapping_new(&format_ident!("entry"), key_ty, offset_lit);
                (
                    quote! { #map_new.get_bytes(entry.key_ref()).read()? },
                    quote! { #map_new.get_bytes(entry.key_ref()).write(&value.#fname)?; },
                    quote! { #map_new.get_bytes(entry.key_ref()).clear()?; },
                )
            }
            None => (
                quote! {
                    ::outbe_primitives::storage::types::Mapping::<#key_ty, #storage_ty>::new(
                        entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                        entry.address(),
                        entry.storage(),
                    ).read(entry.key_ref())?
                },
                quote! {
                    ::outbe_primitives::storage::types::Mapping::<#key_ty, #storage_ty>::new(
                        entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                        entry.address(),
                        entry.storage(),
                    ).write(entry.key_ref(), value.#fname)?;
                },
                quote! {
                    ::outbe_primitives::storage::types::Mapping::<#key_ty, #storage_ty>::new(
                        entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                        entry.address(),
                        entry.storage(),
                    ).get(entry.key_ref()).delete()?;
                },
            ),
        };

        if is_optional_type(&field.ty) {
            accessor_trait_methods.push(quote! {
                fn #fname(&self) -> ::outbe_primitives::storage::dsl::OptionalField<'storage, #key_ty, #storage_ty>;
            });
            accessor_impl_methods.push(quote! {
                fn #fname(&self) -> ::outbe_primitives::storage::dsl::OptionalField<'storage, #key_ty, #storage_ty> {
                    ::outbe_primitives::storage::dsl::OptionalField::new(
                        self.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                        self.address(),
                        self.storage(),
                        self.key(),
                    )
                }
            });
        } else if dynamic_kind.is_some() {
            let map_new = dynamic_bytes_mapping_new(&format_ident!("self"), key_ty, offset_lit);
            accessor_trait_methods.push(quote! {
                fn #fname(&self) -> ::outbe_primitives::storage::types::StorageBytes<'storage>;
            });
            accessor_impl_methods.push(quote! {
                fn #fname(&self) -> ::outbe_primitives::storage::types::StorageBytes<'storage> {
                    #map_new.get_bytes(self.key_ref())
                }
            });
        } else {
            accessor_trait_methods.push(quote! {
                fn #fname(&self) -> ::outbe_primitives::storage::types::Slot<'storage, #storage_ty>;
            });
            accessor_impl_methods.push(quote! {
                fn #fname(&self) -> ::outbe_primitives::storage::types::Slot<'storage, #storage_ty> {
                    ::outbe_primitives::storage::types::Mapping::<#key_ty, #storage_ty>::new(
                        self.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                        self.address(),
                        self.storage(),
                    ).get(self.key_ref())
                }
            });
        }

        load_fields.push(if is_optional_type(&field.ty) {
            quote! { #fname: ::outbe_primitives::storage::dsl::OptionalField::<#key_ty, #storage_ty>::new(
                entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                entry.address(),
                entry.storage(),
                entry.key(),
            ).read()? }
        } else {
            quote! { #fname: #mapping_read }
        });

        write_fields.push(if is_optional_type(&field.ty) {
            quote! {
                ::outbe_primitives::storage::dsl::OptionalField::<#key_ty, #storage_ty>::new(
                    entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                    entry.address(),
                    entry.storage(),
                    entry.key(),
                ).write(value.#fname)?;
            }
        } else {
            mapping_write
        });

        delete_fields.push(if is_optional_type(&field.ty) {
            quote! {
                ::outbe_primitives::storage::dsl::OptionalField::<#key_ty, #storage_ty>::new(
                    entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                    entry.address(),
                    entry.storage(),
                    entry.key(),
                ).delete()?;
            }
        } else {
            mapping_delete
        });

        if field.name == exists_field_ident {
            exists_expr = Some(if is_optional_type(&field.ty) {
                quote! {
                    Ok(::outbe_primitives::storage::dsl::OptionalField::<#key_ty, #storage_ty>::new(
                        entry.base_slot() + ::alloy_primitives::U256::from(#offset_lit),
                        entry.address(),
                        entry.storage(),
                        entry.key(),
                    ).read()?.is_some())
                }
            } else {
                quote! {
                    let value = #mapping_read;
                    Ok(!<#storage_ty as ::outbe_primitives::storage::types::Storable>::to_word(&value).is_zero())
                }
            });
        }
    }

    let exists_expr = exists_expr.ok_or_else(|| {
        syn::Error::new_spanned(
            name,
            format!(
                "exists_field `{}` not found among non-key fields",
                exists_field_ident
            ),
        )
    })?;

    let record_impl = quote! {
        impl ::outbe_primitives::storage::dsl::StorageRecord for #name {
            type Key = #key_ty;
            const SLOTS: u64 = #total_slots;

            fn key(&self) -> Self::Key {
                self.#key_name.clone()
            }

            fn exists(entry: &::outbe_primitives::storage::dsl::RecordEntry<'_, Self::Key, Self>) -> ::outbe_primitives::error::Result<bool> {
                #exists_expr
            }

            fn load(entry: &::outbe_primitives::storage::dsl::RecordEntry<'_, Self::Key, Self>) -> ::outbe_primitives::error::Result<Option<Self>> {
                if !Self::exists(entry)? {
                    return Ok(None);
                }
                Ok(Some(Self {
                    #(#load_fields,)*
                    #key_name: entry.key(),
                }))
            }

            fn create(entry: &::outbe_primitives::storage::dsl::RecordEntry<'_, Self::Key, Self>, value: &Self) -> ::outbe_primitives::error::Result<()> {
                if Self::exists(entry)? {
                    return Err(::outbe_primitives::storage::dsl::existing_record_err(stringify!(#name)));
                }
                #(#write_fields)*
                Ok(())
            }

            fn update(entry: &::outbe_primitives::storage::dsl::RecordEntry<'_, Self::Key, Self>, value: &Self) -> ::outbe_primitives::error::Result<()> {
                if !Self::exists(entry)? {
                    return Err(::outbe_primitives::storage::dsl::missing_record_err(stringify!(#name)));
                }
                #(#write_fields)*
                Ok(())
            }

            fn delete(entry: &::outbe_primitives::storage::dsl::RecordEntry<'_, Self::Key, Self>) -> ::outbe_primitives::error::Result<()> {
                #(#delete_fields)*
                Ok(())
            }
        }

        pub trait #entry_trait_name<'storage> {
            #(#accessor_trait_methods)*
        }

        impl<'storage> #entry_trait_name<'storage> for ::outbe_primitives::storage::dsl::RecordEntry<'storage, #key_ty, #name> {
            #(#accessor_impl_methods)*
        }
    };

    Ok(quote! {
        #cleaned_struct
        #helper_impl
        #record_impl
    })
}
