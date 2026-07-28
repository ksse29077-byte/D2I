pub use root::*;

const _: () = ::planus::check_version_compatibility("planus-1.1.1");

/// The root namespace
///
/// Generated from these locations:
/// * File `schemas\flatbuffers\common.fbs`
#[no_implicit_prelude]
#[allow(dead_code, clippy::needless_lifetimes)]
mod root {
    /// The namespace `D2I`
    ///
    /// Generated from these locations:
    /// * File `schemas\flatbuffers\common.fbs`
    pub mod d2i {
        /// The namespace `D2I.Package`
        ///
        /// Generated from these locations:
        /// * File `schemas\flatbuffers\common.fbs`
        /// * File `schemas\flatbuffers\domain.fbs`
        /// * File `schemas\flatbuffers\evaluation.fbs`
        /// * File `schemas\flatbuffers\execution.fbs`
        /// * File `schemas\flatbuffers\manifest.fbs`
        /// * File `schemas\flatbuffers\policies.fbs`
        /// * File `schemas\flatbuffers\skills.fbs`
        pub mod package {
            /// The table `Provenance` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `Provenance` in the file `schemas\flatbuffers\common.fbs:3`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct Provenance {
                /// The field `id` in the table `Provenance`
                pub id: ::planus::alloc::string::String,
                /// The field `source_path` in the table `Provenance`
                pub source_path: ::planus::alloc::string::String,
                /// The field `line` in the table `Provenance`
                pub line: u32,
                /// The field `field` in the table `Provenance`
                pub field: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `content_hash` in the table `Provenance`
                pub content_hash: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for Provenance {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        source_path: ::core::default::Default::default(),
                        line: 0,
                        field: ::core::default::Default::default(),
                        content_hash: ::core::default::Default::default(),
                    }
                }
            }

            impl Provenance {
                /// Creates a [ProvenanceBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ProvenanceBuilder<()> {
                    ProvenanceBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_source_path: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_line: impl ::planus::WriteAsDefault<u32, u32>,
                    field_field: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_content_hash: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_source_path = field_source_path.prepare(builder);
                    let prepared_line = field_line.prepare(builder, &0);
                    let prepared_field = field_field.prepare(builder);
                    let prepared_content_hash = field_content_hash.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<14> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    if prepared_line.is_some() {
                        table_writer.write_entry::<u32>(2);
                    }
                    if prepared_field.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(3);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(4);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_source_path);
                            if let ::core::option::Option::Some(prepared_line) = prepared_line {
                                object_writer.write::<_, _, 4>(&prepared_line);
                            }
                            if let ::core::option::Option::Some(prepared_field) = prepared_field {
                                object_writer.write::<_, _, 4>(&prepared_field);
                            }
                            object_writer.write::<_, _, 4>(&prepared_content_hash);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<Provenance>> for Provenance {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Provenance> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<Provenance>> for Provenance {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<Provenance>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<Provenance> for Provenance {
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Provenance> {
                    Provenance::create(
                        builder,
                        &self.id,
                        &self.source_path,
                        self.line,
                        &self.field,
                        &self.content_hash,
                    )
                }
            }

            /// Builder for serializing an instance of the [Provenance] type.
            ///
            /// Can be created using the [Provenance::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ProvenanceBuilder<State>(State);

            impl ProvenanceBuilder<()> {
                /// Setter for the [`id` field](Provenance#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> ProvenanceBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    ProvenanceBuilder((value,))
                }
            }

            impl<T0> ProvenanceBuilder<(T0,)> {
                /// Setter for the [`source_path` field](Provenance#structfield.source_path).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn source_path<T1>(self, value: T1) -> ProvenanceBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    ProvenanceBuilder((v0, value))
                }
            }

            impl<T0, T1> ProvenanceBuilder<(T0, T1)> {
                /// Setter for the [`line` field](Provenance#structfield.line).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn line<T2>(self, value: T2) -> ProvenanceBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsDefault<u32, u32>,
                {
                    let (v0, v1) = self.0;
                    ProvenanceBuilder((v0, v1, value))
                }

                /// Sets the [`line` field](Provenance#structfield.line) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn line_as_default(
                    self,
                ) -> ProvenanceBuilder<(T0, T1, ::planus::DefaultValue)> {
                    self.line(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2> ProvenanceBuilder<(T0, T1, T2)> {
                /// Setter for the [`field` field](Provenance#structfield.field).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn field<T3>(self, value: T3) -> ProvenanceBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2) = self.0;
                    ProvenanceBuilder((v0, v1, v2, value))
                }

                /// Sets the [`field` field](Provenance#structfield.field) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn field_as_null(self) -> ProvenanceBuilder<(T0, T1, T2, ())> {
                    self.field(())
                }
            }

            impl<T0, T1, T2, T3> ProvenanceBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`content_hash` field](Provenance#structfield.content_hash).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn content_hash<T4>(self, value: T4) -> ProvenanceBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    ProvenanceBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> ProvenanceBuilder<(T0, T1, T2, T3, T4)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [Provenance].
                #[inline]
                pub fn finish(self, builder: &mut ::planus::Builder) -> ::planus::Offset<Provenance>
                where
                    Self: ::planus::WriteAsOffset<Provenance>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<u32, u32>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<Provenance>>
                for ProvenanceBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<Provenance>;

                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Provenance> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<u32, u32>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<Provenance>>
                for ProvenanceBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<Provenance>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<Provenance>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<u32, u32>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<Provenance> for ProvenanceBuilder<(T0, T1, T2, T3, T4)>
            {
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Provenance> {
                    let (v0, v1, v2, v3, v4) = &self.0;
                    Provenance::create(builder, v0, v1, v2, v3, v4)
                }
            }

            /// Reference to a deserialized [Provenance].
            #[derive(Copy, Clone)]
            pub struct ProvenanceRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ProvenanceRef<'a> {
                /// Getter for the [`id` field](Provenance#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "Provenance", "id")
                }

                /// Getter for the [`source_path` field](Provenance#structfield.source_path).
                #[inline]
                pub fn source_path(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "Provenance", "source_path")
                }

                /// Getter for the [`line` field](Provenance#structfield.line).
                #[inline]
                pub fn line(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(self.0.access(2, "Provenance", "line")?.unwrap_or(0))
                }

                /// Getter for the [`field` field](Provenance#structfield.field).
                #[inline]
                pub fn field(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(3, "Provenance", "field")
                }

                /// Getter for the [`content_hash` field](Provenance#structfield.content_hash).
                #[inline]
                pub fn content_hash(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(4, "Provenance", "content_hash")
                }
            }

            impl<'a> ::core::fmt::Debug for ProvenanceRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ProvenanceRef");
                    f.field("id", &self.id());
                    f.field("source_path", &self.source_path());
                    f.field("line", &self.line());
                    if let ::core::option::Option::Some(field_field) = self.field().transpose() {
                        f.field("field", &field_field);
                    }
                    f.field("content_hash", &self.content_hash());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ProvenanceRef<'a>> for Provenance {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ProvenanceRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        source_path: ::core::convert::Into::into(value.source_path()?),
                        line: ::core::convert::TryInto::try_into(value.line()?)?,
                        field: value.field()?.map(::core::convert::Into::into),
                        content_hash: ::core::convert::Into::into(value.content_hash()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ProvenanceRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ProvenanceRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ProvenanceRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<Provenance>> for Provenance {
                type Value = ::planus::Offset<Provenance>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<Provenance>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ProvenanceRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[ProvenanceRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `StringRecord` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `StringRecord` in the file `schemas\flatbuffers\common.fbs:11`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct StringRecord {
                /// The field `id` in the table `StringRecord`
                pub id: ::planus::alloc::string::String,
                /// The field `kind` in the table `StringRecord`
                pub kind: ::planus::alloc::string::String,
                /// The field `subject` in the table `StringRecord`
                pub subject: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `predicate` in the table `StringRecord`
                pub predicate: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `object` in the table `StringRecord`
                pub object: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `provenance_id` in the table `StringRecord`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for StringRecord {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        kind: ::core::default::Default::default(),
                        subject: ::core::default::Default::default(),
                        predicate: ::core::default::Default::default(),
                        object: ::core::default::Default::default(),
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl StringRecord {
                /// Creates a [StringRecordBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> StringRecordBuilder<()> {
                    StringRecordBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_kind: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_subject: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_predicate: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_object: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_kind = field_kind.prepare(builder);
                    let prepared_subject = field_subject.prepare(builder);
                    let prepared_predicate = field_predicate.prepare(builder);
                    let prepared_object = field_object.prepare(builder);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<16> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    if prepared_subject.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(2);
                    }
                    if prepared_predicate.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(3);
                    }
                    if prepared_object.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(4);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(5);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_kind);
                            if let ::core::option::Option::Some(prepared_subject) = prepared_subject
                            {
                                object_writer.write::<_, _, 4>(&prepared_subject);
                            }
                            if let ::core::option::Option::Some(prepared_predicate) =
                                prepared_predicate
                            {
                                object_writer.write::<_, _, 4>(&prepared_predicate);
                            }
                            if let ::core::option::Option::Some(prepared_object) = prepared_object {
                                object_writer.write::<_, _, 4>(&prepared_object);
                            }
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<StringRecord>> for StringRecord {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<StringRecord> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<StringRecord>> for StringRecord {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<StringRecord>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<StringRecord> for StringRecord {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<StringRecord> {
                    StringRecord::create(
                        builder,
                        &self.id,
                        &self.kind,
                        &self.subject,
                        &self.predicate,
                        &self.object,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [StringRecord] type.
            ///
            /// Can be created using the [StringRecord::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct StringRecordBuilder<State>(State);

            impl StringRecordBuilder<()> {
                /// Setter for the [`id` field](StringRecord#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> StringRecordBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    StringRecordBuilder((value,))
                }
            }

            impl<T0> StringRecordBuilder<(T0,)> {
                /// Setter for the [`kind` field](StringRecord#structfield.kind).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn kind<T1>(self, value: T1) -> StringRecordBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    StringRecordBuilder((v0, value))
                }
            }

            impl<T0, T1> StringRecordBuilder<(T0, T1)> {
                /// Setter for the [`subject` field](StringRecord#structfield.subject).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn subject<T2>(self, value: T2) -> StringRecordBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1) = self.0;
                    StringRecordBuilder((v0, v1, value))
                }

                /// Sets the [`subject` field](StringRecord#structfield.subject) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn subject_as_null(self) -> StringRecordBuilder<(T0, T1, ())> {
                    self.subject(())
                }
            }

            impl<T0, T1, T2> StringRecordBuilder<(T0, T1, T2)> {
                /// Setter for the [`predicate` field](StringRecord#structfield.predicate).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn predicate<T3>(self, value: T3) -> StringRecordBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2) = self.0;
                    StringRecordBuilder((v0, v1, v2, value))
                }

                /// Sets the [`predicate` field](StringRecord#structfield.predicate) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn predicate_as_null(self) -> StringRecordBuilder<(T0, T1, T2, ())> {
                    self.predicate(())
                }
            }

            impl<T0, T1, T2, T3> StringRecordBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`object` field](StringRecord#structfield.object).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn object<T4>(self, value: T4) -> StringRecordBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    StringRecordBuilder((v0, v1, v2, v3, value))
                }

                /// Sets the [`object` field](StringRecord#structfield.object) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn object_as_null(self) -> StringRecordBuilder<(T0, T1, T2, T3, ())> {
                    self.object(())
                }
            }

            impl<T0, T1, T2, T3, T4> StringRecordBuilder<(T0, T1, T2, T3, T4)> {
                /// Setter for the [`provenance_id` field](StringRecord#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T5>(
                    self,
                    value: T5,
                ) -> StringRecordBuilder<(T0, T1, T2, T3, T4, T5)>
                where
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4) = self.0;
                    StringRecordBuilder((v0, v1, v2, v3, v4, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5> StringRecordBuilder<(T0, T1, T2, T3, T4, T5)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [StringRecord].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<StringRecord>
                where
                    Self: ::planus::WriteAsOffset<StringRecord>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<StringRecord>>
                for StringRecordBuilder<(T0, T1, T2, T3, T4, T5)>
            {
                type Prepared = ::planus::Offset<StringRecord>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<StringRecord> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<StringRecord>>
                for StringRecordBuilder<(T0, T1, T2, T3, T4, T5)>
            {
                type Prepared = ::planus::Offset<StringRecord>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<StringRecord>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<StringRecord>
                for StringRecordBuilder<(T0, T1, T2, T3, T4, T5)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<StringRecord> {
                    let (v0, v1, v2, v3, v4, v5) = &self.0;
                    StringRecord::create(builder, v0, v1, v2, v3, v4, v5)
                }
            }

            /// Reference to a deserialized [StringRecord].
            #[derive(Copy, Clone)]
            pub struct StringRecordRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> StringRecordRef<'a> {
                /// Getter for the [`id` field](StringRecord#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "StringRecord", "id")
                }

                /// Getter for the [`kind` field](StringRecord#structfield.kind).
                #[inline]
                pub fn kind(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "StringRecord", "kind")
                }

                /// Getter for the [`subject` field](StringRecord#structfield.subject).
                #[inline]
                pub fn subject(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(2, "StringRecord", "subject")
                }

                /// Getter for the [`predicate` field](StringRecord#structfield.predicate).
                #[inline]
                pub fn predicate(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(3, "StringRecord", "predicate")
                }

                /// Getter for the [`object` field](StringRecord#structfield.object).
                #[inline]
                pub fn object(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(4, "StringRecord", "object")
                }

                /// Getter for the [`provenance_id` field](StringRecord#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(5, "StringRecord", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for StringRecordRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("StringRecordRef");
                    f.field("id", &self.id());
                    f.field("kind", &self.kind());
                    if let ::core::option::Option::Some(field_subject) = self.subject().transpose()
                    {
                        f.field("subject", &field_subject);
                    }
                    if let ::core::option::Option::Some(field_predicate) =
                        self.predicate().transpose()
                    {
                        f.field("predicate", &field_predicate);
                    }
                    if let ::core::option::Option::Some(field_object) = self.object().transpose() {
                        f.field("object", &field_object);
                    }
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<StringRecordRef<'a>> for StringRecord {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: StringRecordRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        kind: ::core::convert::Into::into(value.kind()?),
                        subject: value.subject()?.map(::core::convert::Into::into),
                        predicate: value.predicate()?.map(::core::convert::Into::into),
                        object: value.object()?.map(::core::convert::Into::into),
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for StringRecordRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for StringRecordRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[StringRecordRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<StringRecord>> for StringRecord {
                type Value = ::planus::Offset<StringRecord>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<StringRecord>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for StringRecordRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[StringRecordRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `DomainBundle` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `DomainBundle` in the file `schemas\flatbuffers\domain.fbs:5`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct DomainBundle {
                /// The field `schema_version` in the table `DomainBundle`
                pub schema_version: u32,
                /// The field `domain_id` in the table `DomainBundle`
                pub domain_id: ::planus::alloc::string::String,
                /// The field `domain_version` in the table `DomainBundle`
                pub domain_version: ::planus::alloc::string::String,
                /// The field `name` in the table `DomainBundle`
                pub name: ::planus::alloc::string::String,
                /// The field `languages` in the table `DomainBundle`
                pub languages: ::planus::alloc::vec::Vec<::planus::alloc::string::String>,
                /// The field `entities` in the table `DomainBundle`
                pub entities: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `relations` in the table `DomainBundle`
                pub relations: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `terms` in the table `DomainBundle`
                pub terms: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `facts` in the table `DomainBundle`
                pub facts: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `documents` in the table `DomainBundle`
                pub documents: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `procedures` in the table `DomainBundle`
                pub procedures: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `rules` in the table `DomainBundle`
                pub rules: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `examples` in the table `DomainBundle`
                pub examples: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `outcomes` in the table `DomainBundle`
                pub outcomes: ::planus::alloc::vec::Vec<self::StringRecord>,
                /// The field `provenance` in the table `DomainBundle`
                pub provenance: ::planus::alloc::vec::Vec<self::Provenance>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for DomainBundle {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        domain_id: ::core::default::Default::default(),
                        domain_version: ::core::default::Default::default(),
                        name: ::core::default::Default::default(),
                        languages: ::core::default::Default::default(),
                        entities: ::core::default::Default::default(),
                        relations: ::core::default::Default::default(),
                        terms: ::core::default::Default::default(),
                        facts: ::core::default::Default::default(),
                        documents: ::core::default::Default::default(),
                        procedures: ::core::default::Default::default(),
                        rules: ::core::default::Default::default(),
                        examples: ::core::default::Default::default(),
                        outcomes: ::core::default::Default::default(),
                        provenance: ::core::default::Default::default(),
                    }
                }
            }

            impl DomainBundle {
                /// Creates a [DomainBundleBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> DomainBundleBuilder<()> {
                    DomainBundleBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_domain_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_domain_version: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_name: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_languages: impl ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    field_entities: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_relations: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_terms: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_facts: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_documents: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_procedures: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_rules: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_examples: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_outcomes: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::StringRecord>]>,
                    >,
                    field_provenance: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::Provenance>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_domain_id = field_domain_id.prepare(builder);
                    let prepared_domain_version = field_domain_version.prepare(builder);
                    let prepared_name = field_name.prepare(builder);
                    let prepared_languages = field_languages.prepare(builder);
                    let prepared_entities = field_entities.prepare(builder);
                    let prepared_relations = field_relations.prepare(builder);
                    let prepared_terms = field_terms.prepare(builder);
                    let prepared_facts = field_facts.prepare(builder);
                    let prepared_documents = field_documents.prepare(builder);
                    let prepared_procedures = field_procedures.prepare(builder);
                    let prepared_rules = field_rules.prepare(builder);
                    let prepared_examples = field_examples.prepare(builder);
                    let prepared_outcomes = field_outcomes.prepare(builder);
                    let prepared_provenance = field_provenance.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<34> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<str>]>>(4);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(5);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(6);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(7);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(8);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(9);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(
                            10,
                        );
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(
                            11,
                        );
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(
                            12,
                        );
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::StringRecord>]>>(
                            13,
                        );
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::Provenance>]>>(14);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_domain_id);
                            object_writer.write::<_, _, 4>(&prepared_domain_version);
                            object_writer.write::<_, _, 4>(&prepared_name);
                            object_writer.write::<_, _, 4>(&prepared_languages);
                            object_writer.write::<_, _, 4>(&prepared_entities);
                            object_writer.write::<_, _, 4>(&prepared_relations);
                            object_writer.write::<_, _, 4>(&prepared_terms);
                            object_writer.write::<_, _, 4>(&prepared_facts);
                            object_writer.write::<_, _, 4>(&prepared_documents);
                            object_writer.write::<_, _, 4>(&prepared_procedures);
                            object_writer.write::<_, _, 4>(&prepared_rules);
                            object_writer.write::<_, _, 4>(&prepared_examples);
                            object_writer.write::<_, _, 4>(&prepared_outcomes);
                            object_writer.write::<_, _, 4>(&prepared_provenance);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<DomainBundle>> for DomainBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<DomainBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<DomainBundle>> for DomainBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<DomainBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<DomainBundle> for DomainBundle {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<DomainBundle> {
                    DomainBundle::create(
                        builder,
                        self.schema_version,
                        &self.domain_id,
                        &self.domain_version,
                        &self.name,
                        &self.languages,
                        &self.entities,
                        &self.relations,
                        &self.terms,
                        &self.facts,
                        &self.documents,
                        &self.procedures,
                        &self.rules,
                        &self.examples,
                        &self.outcomes,
                        &self.provenance,
                    )
                }
            }

            /// Builder for serializing an instance of the [DomainBundle] type.
            ///
            /// Can be created using the [DomainBundle::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct DomainBundleBuilder<State>(State);

            impl DomainBundleBuilder<()> {
                /// Setter for the [`schema_version` field](DomainBundle#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> DomainBundleBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    DomainBundleBuilder((value,))
                }

                /// Sets the [`schema_version` field](DomainBundle#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> DomainBundleBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> DomainBundleBuilder<(T0,)> {
                /// Setter for the [`domain_id` field](DomainBundle#structfield.domain_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn domain_id<T1>(self, value: T1) -> DomainBundleBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    DomainBundleBuilder((v0, value))
                }
            }

            impl<T0, T1> DomainBundleBuilder<(T0, T1)> {
                /// Setter for the [`domain_version` field](DomainBundle#structfield.domain_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn domain_version<T2>(self, value: T2) -> DomainBundleBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    DomainBundleBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> DomainBundleBuilder<(T0, T1, T2)> {
                /// Setter for the [`name` field](DomainBundle#structfield.name).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn name<T3>(self, value: T3) -> DomainBundleBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    DomainBundleBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> DomainBundleBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`languages` field](DomainBundle#structfield.languages).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn languages<T4>(self, value: T4) -> DomainBundleBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> DomainBundleBuilder<(T0, T1, T2, T3, T4)> {
                /// Setter for the [`entities` field](DomainBundle#structfield.entities).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn entities<T5>(
                    self,
                    value: T5,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5)>
                where
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5)> {
                /// Setter for the [`relations` field](DomainBundle#structfield.relations).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn relations<T6>(
                    self,
                    value: T6,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)>
                where
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)> {
                /// Setter for the [`terms` field](DomainBundle#structfield.terms).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn terms<T7>(
                    self,
                    value: T7,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)>
                where
                    T7: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, v6, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)> {
                /// Setter for the [`facts` field](DomainBundle#structfield.facts).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn facts<T8>(
                    self,
                    value: T8,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)>
                where
                    T8: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, v6, v7, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)> {
                /// Setter for the [`documents` field](DomainBundle#structfield.documents).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn documents<T9>(
                    self,
                    value: T9,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
                where
                    T9: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9>
                DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
            {
                /// Setter for the [`procedures` field](DomainBundle#structfield.procedures).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn procedures<T10>(
                    self,
                    value: T10,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
                where
                    T10:
                        ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>
                DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
            {
                /// Setter for the [`rules` field](DomainBundle#structfield.rules).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn rules<T11>(
                    self,
                    value: T11,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
                where
                    T11:
                        ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>
                DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
            {
                /// Setter for the [`examples` field](DomainBundle#structfield.examples).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn examples<T12>(
                    self,
                    value: T12,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
                where
                    T12:
                        ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) = self.0;
                    DomainBundleBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>
                DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                /// Setter for the [`outcomes` field](DomainBundle#structfield.outcomes).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn outcomes<T13>(
                    self,
                    value: T13,
                ) -> DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13)>
                where
                    T13:
                        ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) = self.0;
                    DomainBundleBuilder((
                        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, value,
                    ))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13>
                DomainBundleBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13)>
            {
                /// Setter for the [`provenance` field](DomainBundle#structfield.provenance).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance<T14>(
                    self,
                    value: T14,
                ) -> DomainBundleBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
                where
                    T14: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Provenance>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13) = self.0;
                    DomainBundleBuilder((
                        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, value,
                    ))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14>
                DomainBundleBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
            {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [DomainBundle].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<DomainBundle>
                where
                    Self: ::planus::WriteAsOffset<DomainBundle>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T7: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T8: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T9: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T10: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T13: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T14: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Provenance>]>>,
                > ::planus::WriteAs<::planus::Offset<DomainBundle>>
                for DomainBundleBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
            {
                type Prepared = ::planus::Offset<DomainBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<DomainBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T7: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T8: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T9: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T10: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T13: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T14: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Provenance>]>>,
                > ::planus::WriteAsOptional<::planus::Offset<DomainBundle>>
                for DomainBundleBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
            {
                type Prepared = ::planus::Offset<DomainBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<DomainBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T7: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T8: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T9: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T10: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T13: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::StringRecord>]>>,
                    T14: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Provenance>]>>,
                > ::planus::WriteAsOffset<DomainBundle>
                for DomainBundleBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<DomainBundle> {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) = &self.0;
                    DomainBundle::create(
                        builder, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14,
                    )
                }
            }

            /// Reference to a deserialized [DomainBundle].
            #[derive(Copy, Clone)]
            pub struct DomainBundleRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> DomainBundleRef<'a> {
                /// Getter for the [`schema_version` field](DomainBundle#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "DomainBundle", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`domain_id` field](DomainBundle#structfield.domain_id).
                #[inline]
                pub fn domain_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "DomainBundle", "domain_id")
                }

                /// Getter for the [`domain_version` field](DomainBundle#structfield.domain_version).
                #[inline]
                pub fn domain_version(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "DomainBundle", "domain_version")
                }

                /// Getter for the [`name` field](DomainBundle#structfield.name).
                #[inline]
                pub fn name(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(3, "DomainBundle", "name")
                }

                /// Getter for the [`languages` field](DomainBundle#structfield.languages).
                #[inline]
                pub fn languages(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<&'a ::core::primitive::str>>,
                > {
                    self.0.access_required(4, "DomainBundle", "languages")
                }

                /// Getter for the [`entities` field](DomainBundle#structfield.entities).
                #[inline]
                pub fn entities(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(5, "DomainBundle", "entities")
                }

                /// Getter for the [`relations` field](DomainBundle#structfield.relations).
                #[inline]
                pub fn relations(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(6, "DomainBundle", "relations")
                }

                /// Getter for the [`terms` field](DomainBundle#structfield.terms).
                #[inline]
                pub fn terms(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(7, "DomainBundle", "terms")
                }

                /// Getter for the [`facts` field](DomainBundle#structfield.facts).
                #[inline]
                pub fn facts(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(8, "DomainBundle", "facts")
                }

                /// Getter for the [`documents` field](DomainBundle#structfield.documents).
                #[inline]
                pub fn documents(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(9, "DomainBundle", "documents")
                }

                /// Getter for the [`procedures` field](DomainBundle#structfield.procedures).
                #[inline]
                pub fn procedures(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(10, "DomainBundle", "procedures")
                }

                /// Getter for the [`rules` field](DomainBundle#structfield.rules).
                #[inline]
                pub fn rules(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(11, "DomainBundle", "rules")
                }

                /// Getter for the [`examples` field](DomainBundle#structfield.examples).
                #[inline]
                pub fn examples(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(12, "DomainBundle", "examples")
                }

                /// Getter for the [`outcomes` field](DomainBundle#structfield.outcomes).
                #[inline]
                pub fn outcomes(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::StringRecordRef<'a>>>,
                > {
                    self.0.access_required(13, "DomainBundle", "outcomes")
                }

                /// Getter for the [`provenance` field](DomainBundle#structfield.provenance).
                #[inline]
                pub fn provenance(
                    &self,
                ) -> ::planus::Result<::planus::Vector<'a, ::planus::Result<self::ProvenanceRef<'a>>>>
                {
                    self.0.access_required(14, "DomainBundle", "provenance")
                }
            }

            impl<'a> ::core::fmt::Debug for DomainBundleRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("DomainBundleRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("domain_id", &self.domain_id());
                    f.field("domain_version", &self.domain_version());
                    f.field("name", &self.name());
                    f.field("languages", &self.languages());
                    f.field("entities", &self.entities());
                    f.field("relations", &self.relations());
                    f.field("terms", &self.terms());
                    f.field("facts", &self.facts());
                    f.field("documents", &self.documents());
                    f.field("procedures", &self.procedures());
                    f.field("rules", &self.rules());
                    f.field("examples", &self.examples());
                    f.field("outcomes", &self.outcomes());
                    f.field("provenance", &self.provenance());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<DomainBundleRef<'a>> for DomainBundle {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: DomainBundleRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        domain_id: ::core::convert::Into::into(value.domain_id()?),
                        domain_version: ::core::convert::Into::into(value.domain_version()?),
                        name: ::core::convert::Into::into(value.name()?),
                        languages: value.languages()?.to_vec_result()?,
                        entities: value.entities()?.to_vec_result()?,
                        relations: value.relations()?.to_vec_result()?,
                        terms: value.terms()?.to_vec_result()?,
                        facts: value.facts()?.to_vec_result()?,
                        documents: value.documents()?.to_vec_result()?,
                        procedures: value.procedures()?.to_vec_result()?,
                        rules: value.rules()?.to_vec_result()?,
                        examples: value.examples()?.to_vec_result()?,
                        outcomes: value.outcomes()?.to_vec_result()?,
                        provenance: value.provenance()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for DomainBundleRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for DomainBundleRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[DomainBundleRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<DomainBundle>> for DomainBundle {
                type Value = ::planus::Offset<DomainBundle>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<DomainBundle>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for DomainBundleRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[DomainBundleRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `EvaluationCase` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `EvaluationCase` in the file `schemas\flatbuffers\evaluation.fbs:5`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct EvaluationCase {
                /// The field `id` in the table `EvaluationCase`
                pub id: ::planus::alloc::string::String,
                /// The field `skill_id` in the table `EvaluationCase`
                pub skill_id: ::planus::alloc::string::String,
                /// The field `request_json` in the table `EvaluationCase`
                pub request_json: ::planus::alloc::string::String,
                /// The field `expected_json` in the table `EvaluationCase`
                pub expected_json: ::planus::alloc::string::String,
                /// The field `provenance_id` in the table `EvaluationCase`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for EvaluationCase {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        skill_id: ::core::default::Default::default(),
                        request_json: ::core::default::Default::default(),
                        expected_json: ::core::default::Default::default(),
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl EvaluationCase {
                /// Creates a [EvaluationCaseBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> EvaluationCaseBuilder<()> {
                    EvaluationCaseBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_skill_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_request_json: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_expected_json: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_skill_id = field_skill_id.prepare(builder);
                    let prepared_request_json = field_request_json.prepare(builder);
                    let prepared_expected_json = field_expected_json.prepare(builder);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<14> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    table_writer.write_entry::<::planus::Offset<str>>(4);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_skill_id);
                            object_writer.write::<_, _, 4>(&prepared_request_json);
                            object_writer.write::<_, _, 4>(&prepared_expected_json);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<EvaluationCase>> for EvaluationCase {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationCase> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<EvaluationCase>> for EvaluationCase {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<EvaluationCase>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<EvaluationCase> for EvaluationCase {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationCase> {
                    EvaluationCase::create(
                        builder,
                        &self.id,
                        &self.skill_id,
                        &self.request_json,
                        &self.expected_json,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [EvaluationCase] type.
            ///
            /// Can be created using the [EvaluationCase::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct EvaluationCaseBuilder<State>(State);

            impl EvaluationCaseBuilder<()> {
                /// Setter for the [`id` field](EvaluationCase#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> EvaluationCaseBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    EvaluationCaseBuilder((value,))
                }
            }

            impl<T0> EvaluationCaseBuilder<(T0,)> {
                /// Setter for the [`skill_id` field](EvaluationCase#structfield.skill_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn skill_id<T1>(self, value: T1) -> EvaluationCaseBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    EvaluationCaseBuilder((v0, value))
                }
            }

            impl<T0, T1> EvaluationCaseBuilder<(T0, T1)> {
                /// Setter for the [`request_json` field](EvaluationCase#structfield.request_json).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn request_json<T2>(self, value: T2) -> EvaluationCaseBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    EvaluationCaseBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> EvaluationCaseBuilder<(T0, T1, T2)> {
                /// Setter for the [`expected_json` field](EvaluationCase#structfield.expected_json).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn expected_json<T3>(self, value: T3) -> EvaluationCaseBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    EvaluationCaseBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> EvaluationCaseBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`provenance_id` field](EvaluationCase#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T4>(
                    self,
                    value: T4,
                ) -> EvaluationCaseBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    EvaluationCaseBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> EvaluationCaseBuilder<(T0, T1, T2, T3, T4)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [EvaluationCase].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationCase>
                where
                    Self: ::planus::WriteAsOffset<EvaluationCase>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<EvaluationCase>>
                for EvaluationCaseBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<EvaluationCase>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationCase> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<EvaluationCase>>
                for EvaluationCaseBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<EvaluationCase>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<EvaluationCase>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<EvaluationCase>
                for EvaluationCaseBuilder<(T0, T1, T2, T3, T4)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationCase> {
                    let (v0, v1, v2, v3, v4) = &self.0;
                    EvaluationCase::create(builder, v0, v1, v2, v3, v4)
                }
            }

            /// Reference to a deserialized [EvaluationCase].
            #[derive(Copy, Clone)]
            pub struct EvaluationCaseRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> EvaluationCaseRef<'a> {
                /// Getter for the [`id` field](EvaluationCase#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "EvaluationCase", "id")
                }

                /// Getter for the [`skill_id` field](EvaluationCase#structfield.skill_id).
                #[inline]
                pub fn skill_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "EvaluationCase", "skill_id")
                }

                /// Getter for the [`request_json` field](EvaluationCase#structfield.request_json).
                #[inline]
                pub fn request_json(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "EvaluationCase", "request_json")
                }

                /// Getter for the [`expected_json` field](EvaluationCase#structfield.expected_json).
                #[inline]
                pub fn expected_json(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(3, "EvaluationCase", "expected_json")
                }

                /// Getter for the [`provenance_id` field](EvaluationCase#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(4, "EvaluationCase", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for EvaluationCaseRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("EvaluationCaseRef");
                    f.field("id", &self.id());
                    f.field("skill_id", &self.skill_id());
                    f.field("request_json", &self.request_json());
                    f.field("expected_json", &self.expected_json());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<EvaluationCaseRef<'a>> for EvaluationCase {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: EvaluationCaseRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        skill_id: ::core::convert::Into::into(value.skill_id()?),
                        request_json: ::core::convert::Into::into(value.request_json()?),
                        expected_json: ::core::convert::Into::into(value.expected_json()?),
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for EvaluationCaseRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for EvaluationCaseRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[EvaluationCaseRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<EvaluationCase>> for EvaluationCase {
                type Value = ::planus::Offset<EvaluationCase>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<EvaluationCase>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for EvaluationCaseRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[EvaluationCaseRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `MetricSpec` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `MetricSpec` in the file `schemas\flatbuffers\evaluation.fbs:13`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct MetricSpec {
                /// The field `id` in the table `MetricSpec`
                pub id: ::planus::alloc::string::String,
                /// The field `threshold` in the table `MetricSpec`
                pub threshold: f64,
                /// The field `higher_is_better` in the table `MetricSpec`
                pub higher_is_better: bool,
                /// The field `provenance_id` in the table `MetricSpec`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for MetricSpec {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        threshold: 0.0,
                        higher_is_better: false,
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl MetricSpec {
                /// Creates a [MetricSpecBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> MetricSpecBuilder<()> {
                    MetricSpecBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_threshold: impl ::planus::WriteAsDefault<f64, f64>,
                    field_higher_is_better: impl ::planus::WriteAsDefault<bool, bool>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_threshold = field_threshold.prepare(builder, &0.0);
                    let prepared_higher_is_better = field_higher_is_better.prepare(builder, &false);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<12> =
                        ::core::default::Default::default();
                    if prepared_threshold.is_some() {
                        table_writer.write_entry::<f64>(1);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    if prepared_higher_is_better.is_some() {
                        table_writer.write_entry::<bool>(2);
                    }

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_threshold) =
                                prepared_threshold
                            {
                                object_writer.write::<_, _, 8>(&prepared_threshold);
                            }
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                            if let ::core::option::Option::Some(prepared_higher_is_better) =
                                prepared_higher_is_better
                            {
                                object_writer.write::<_, _, 1>(&prepared_higher_is_better);
                            }
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<MetricSpec>> for MetricSpec {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<MetricSpec> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<MetricSpec>> for MetricSpec {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<MetricSpec>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<MetricSpec> for MetricSpec {
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<MetricSpec> {
                    MetricSpec::create(
                        builder,
                        &self.id,
                        self.threshold,
                        self.higher_is_better,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [MetricSpec] type.
            ///
            /// Can be created using the [MetricSpec::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct MetricSpecBuilder<State>(State);

            impl MetricSpecBuilder<()> {
                /// Setter for the [`id` field](MetricSpec#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> MetricSpecBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    MetricSpecBuilder((value,))
                }
            }

            impl<T0> MetricSpecBuilder<(T0,)> {
                /// Setter for the [`threshold` field](MetricSpec#structfield.threshold).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn threshold<T1>(self, value: T1) -> MetricSpecBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAsDefault<f64, f64>,
                {
                    let (v0,) = self.0;
                    MetricSpecBuilder((v0, value))
                }

                /// Sets the [`threshold` field](MetricSpec#structfield.threshold) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn threshold_as_default(
                    self,
                ) -> MetricSpecBuilder<(T0, ::planus::DefaultValue)> {
                    self.threshold(::planus::DefaultValue)
                }
            }

            impl<T0, T1> MetricSpecBuilder<(T0, T1)> {
                /// Setter for the [`higher_is_better` field](MetricSpec#structfield.higher_is_better).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn higher_is_better<T2>(self, value: T2) -> MetricSpecBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1) = self.0;
                    MetricSpecBuilder((v0, v1, value))
                }

                /// Sets the [`higher_is_better` field](MetricSpec#structfield.higher_is_better) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn higher_is_better_as_default(
                    self,
                ) -> MetricSpecBuilder<(T0, T1, ::planus::DefaultValue)> {
                    self.higher_is_better(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2> MetricSpecBuilder<(T0, T1, T2)> {
                /// Setter for the [`provenance_id` field](MetricSpec#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T3>(self, value: T3) -> MetricSpecBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    MetricSpecBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> MetricSpecBuilder<(T0, T1, T2, T3)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [MetricSpec].
                #[inline]
                pub fn finish(self, builder: &mut ::planus::Builder) -> ::planus::Offset<MetricSpec>
                where
                    Self: ::planus::WriteAsOffset<MetricSpec>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<f64, f64>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<MetricSpec>>
                for MetricSpecBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<MetricSpec>;

                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<MetricSpec> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<f64, f64>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<MetricSpec>>
                for MetricSpecBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<MetricSpec>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<MetricSpec>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<f64, f64>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<MetricSpec> for MetricSpecBuilder<(T0, T1, T2, T3)>
            {
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<MetricSpec> {
                    let (v0, v1, v2, v3) = &self.0;
                    MetricSpec::create(builder, v0, v1, v2, v3)
                }
            }

            /// Reference to a deserialized [MetricSpec].
            #[derive(Copy, Clone)]
            pub struct MetricSpecRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> MetricSpecRef<'a> {
                /// Getter for the [`id` field](MetricSpec#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "MetricSpec", "id")
                }

                /// Getter for the [`threshold` field](MetricSpec#structfield.threshold).
                #[inline]
                pub fn threshold(&self) -> ::planus::Result<f64> {
                    ::core::result::Result::Ok(
                        self.0.access(1, "MetricSpec", "threshold")?.unwrap_or(0.0),
                    )
                }

                /// Getter for the [`higher_is_better` field](MetricSpec#structfield.higher_is_better).
                #[inline]
                pub fn higher_is_better(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(2, "MetricSpec", "higher_is_better")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`provenance_id` field](MetricSpec#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(3, "MetricSpec", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for MetricSpecRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("MetricSpecRef");
                    f.field("id", &self.id());
                    f.field("threshold", &self.threshold());
                    f.field("higher_is_better", &self.higher_is_better());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<MetricSpecRef<'a>> for MetricSpec {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: MetricSpecRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        threshold: ::core::convert::TryInto::try_into(value.threshold()?)?,
                        higher_is_better: ::core::convert::TryInto::try_into(
                            value.higher_is_better()?,
                        )?,
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for MetricSpecRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for MetricSpecRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[MetricSpecRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<MetricSpec>> for MetricSpec {
                type Value = ::planus::Offset<MetricSpec>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<MetricSpec>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for MetricSpecRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[MetricSpecRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `CriticalErrorCondition` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `CriticalErrorCondition` in the file `schemas\flatbuffers\evaluation.fbs:20`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct CriticalErrorCondition {
                /// The field `id` in the table `CriticalErrorCondition`
                pub id: ::planus::alloc::string::String,
                /// The field `expression` in the table `CriticalErrorCondition`
                pub expression: ::planus::alloc::string::String,
                /// The field `maximum_rate` in the table `CriticalErrorCondition`
                pub maximum_rate: f64,
                /// The field `provenance_id` in the table `CriticalErrorCondition`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for CriticalErrorCondition {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        expression: ::core::default::Default::default(),
                        maximum_rate: 0.0,
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl CriticalErrorCondition {
                /// Creates a [CriticalErrorConditionBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> CriticalErrorConditionBuilder<()> {
                    CriticalErrorConditionBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_expression: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_maximum_rate: impl ::planus::WriteAsDefault<f64, f64>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_expression = field_expression.prepare(builder);
                    let prepared_maximum_rate = field_maximum_rate.prepare(builder, &0.0);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<12> =
                        ::core::default::Default::default();
                    if prepared_maximum_rate.is_some() {
                        table_writer.write_entry::<f64>(2);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(3);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_maximum_rate) =
                                prepared_maximum_rate
                            {
                                object_writer.write::<_, _, 8>(&prepared_maximum_rate);
                            }
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_expression);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<CriticalErrorCondition>> for CriticalErrorCondition {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<CriticalErrorCondition> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<CriticalErrorCondition>>
                for CriticalErrorCondition
            {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<CriticalErrorCondition>>
                {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<CriticalErrorCondition> for CriticalErrorCondition {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<CriticalErrorCondition> {
                    CriticalErrorCondition::create(
                        builder,
                        &self.id,
                        &self.expression,
                        self.maximum_rate,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [CriticalErrorCondition] type.
            ///
            /// Can be created using the [CriticalErrorCondition::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct CriticalErrorConditionBuilder<State>(State);

            impl CriticalErrorConditionBuilder<()> {
                /// Setter for the [`id` field](CriticalErrorCondition#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> CriticalErrorConditionBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    CriticalErrorConditionBuilder((value,))
                }
            }

            impl<T0> CriticalErrorConditionBuilder<(T0,)> {
                /// Setter for the [`expression` field](CriticalErrorCondition#structfield.expression).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn expression<T1>(self, value: T1) -> CriticalErrorConditionBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    CriticalErrorConditionBuilder((v0, value))
                }
            }

            impl<T0, T1> CriticalErrorConditionBuilder<(T0, T1)> {
                /// Setter for the [`maximum_rate` field](CriticalErrorCondition#structfield.maximum_rate).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn maximum_rate<T2>(
                    self,
                    value: T2,
                ) -> CriticalErrorConditionBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsDefault<f64, f64>,
                {
                    let (v0, v1) = self.0;
                    CriticalErrorConditionBuilder((v0, v1, value))
                }

                /// Sets the [`maximum_rate` field](CriticalErrorCondition#structfield.maximum_rate) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn maximum_rate_as_default(
                    self,
                ) -> CriticalErrorConditionBuilder<(T0, T1, ::planus::DefaultValue)>
                {
                    self.maximum_rate(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2> CriticalErrorConditionBuilder<(T0, T1, T2)> {
                /// Setter for the [`provenance_id` field](CriticalErrorCondition#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T3>(
                    self,
                    value: T3,
                ) -> CriticalErrorConditionBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    CriticalErrorConditionBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> CriticalErrorConditionBuilder<(T0, T1, T2, T3)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [CriticalErrorCondition].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<CriticalErrorCondition>
                where
                    Self: ::planus::WriteAsOffset<CriticalErrorCondition>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<f64, f64>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<CriticalErrorCondition>>
                for CriticalErrorConditionBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<CriticalErrorCondition>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<CriticalErrorCondition> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<f64, f64>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<CriticalErrorCondition>>
                for CriticalErrorConditionBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<CriticalErrorCondition>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<CriticalErrorCondition>>
                {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<f64, f64>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<CriticalErrorCondition>
                for CriticalErrorConditionBuilder<(T0, T1, T2, T3)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<CriticalErrorCondition> {
                    let (v0, v1, v2, v3) = &self.0;
                    CriticalErrorCondition::create(builder, v0, v1, v2, v3)
                }
            }

            /// Reference to a deserialized [CriticalErrorCondition].
            #[derive(Copy, Clone)]
            pub struct CriticalErrorConditionRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> CriticalErrorConditionRef<'a> {
                /// Getter for the [`id` field](CriticalErrorCondition#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "CriticalErrorCondition", "id")
                }

                /// Getter for the [`expression` field](CriticalErrorCondition#structfield.expression).
                #[inline]
                pub fn expression(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(1, "CriticalErrorCondition", "expression")
                }

                /// Getter for the [`maximum_rate` field](CriticalErrorCondition#structfield.maximum_rate).
                #[inline]
                pub fn maximum_rate(&self) -> ::planus::Result<f64> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(2, "CriticalErrorCondition", "maximum_rate")?
                            .unwrap_or(0.0),
                    )
                }

                /// Getter for the [`provenance_id` field](CriticalErrorCondition#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(3, "CriticalErrorCondition", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for CriticalErrorConditionRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("CriticalErrorConditionRef");
                    f.field("id", &self.id());
                    f.field("expression", &self.expression());
                    f.field("maximum_rate", &self.maximum_rate());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<CriticalErrorConditionRef<'a>> for CriticalErrorCondition {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: CriticalErrorConditionRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        expression: ::core::convert::Into::into(value.expression()?),
                        maximum_rate: ::core::convert::TryInto::try_into(value.maximum_rate()?)?,
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for CriticalErrorConditionRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for CriticalErrorConditionRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[CriticalErrorConditionRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<CriticalErrorCondition>>
                for CriticalErrorCondition
            {
                type Value = ::planus::Offset<CriticalErrorCondition>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<CriticalErrorCondition>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for CriticalErrorConditionRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[CriticalErrorConditionRef]",
                            "read_as_root",
                            0,
                        )
                    })
                }
            }

            /// The table `EvaluationBundle` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `EvaluationBundle` in the file `schemas\flatbuffers\evaluation.fbs:27`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct EvaluationBundle {
                /// The field `schema_version` in the table `EvaluationBundle`
                pub schema_version: u32,
                /// The field `cases` in the table `EvaluationBundle`
                pub cases: ::planus::alloc::vec::Vec<self::EvaluationCase>,
                /// The field `metrics` in the table `EvaluationBundle`
                pub metrics: ::planus::alloc::vec::Vec<self::MetricSpec>,
                /// The field `critical_errors` in the table `EvaluationBundle`
                pub critical_errors: ::planus::alloc::vec::Vec<self::CriticalErrorCondition>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for EvaluationBundle {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        cases: ::core::default::Default::default(),
                        metrics: ::core::default::Default::default(),
                        critical_errors: ::core::default::Default::default(),
                    }
                }
            }

            impl EvaluationBundle {
                /// Creates a [EvaluationBundleBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> EvaluationBundleBuilder<()> {
                    EvaluationBundleBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_cases: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::EvaluationCase>]>,
                    >,
                    field_metrics: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::MetricSpec>]>,
                    >,
                    field_critical_errors: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::CriticalErrorCondition>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_cases = field_cases.prepare(builder);
                    let prepared_metrics = field_metrics.prepare(builder);
                    let prepared_critical_errors = field_critical_errors.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<12> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::EvaluationCase>]>>(
                            1,
                        );
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::MetricSpec>]>>(2);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<self::CriticalErrorCondition>]>>(3);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_cases);
                            object_writer.write::<_, _, 4>(&prepared_metrics);
                            object_writer.write::<_, _, 4>(&prepared_critical_errors);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<EvaluationBundle>> for EvaluationBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<EvaluationBundle>> for EvaluationBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<EvaluationBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<EvaluationBundle> for EvaluationBundle {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationBundle> {
                    EvaluationBundle::create(
                        builder,
                        self.schema_version,
                        &self.cases,
                        &self.metrics,
                        &self.critical_errors,
                    )
                }
            }

            /// Builder for serializing an instance of the [EvaluationBundle] type.
            ///
            /// Can be created using the [EvaluationBundle::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct EvaluationBundleBuilder<State>(State);

            impl EvaluationBundleBuilder<()> {
                /// Setter for the [`schema_version` field](EvaluationBundle#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> EvaluationBundleBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    EvaluationBundleBuilder((value,))
                }

                /// Sets the [`schema_version` field](EvaluationBundle#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> EvaluationBundleBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> EvaluationBundleBuilder<(T0,)> {
                /// Setter for the [`cases` field](EvaluationBundle#structfield.cases).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn cases<T1>(self, value: T1) -> EvaluationBundleBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::EvaluationCase>]>,
                    >,
                {
                    let (v0,) = self.0;
                    EvaluationBundleBuilder((v0, value))
                }
            }

            impl<T0, T1> EvaluationBundleBuilder<(T0, T1)> {
                /// Setter for the [`metrics` field](EvaluationBundle#structfield.metrics).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn metrics<T2>(self, value: T2) -> EvaluationBundleBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::MetricSpec>]>>,
                {
                    let (v0, v1) = self.0;
                    EvaluationBundleBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> EvaluationBundleBuilder<(T0, T1, T2)> {
                /// Setter for the [`critical_errors` field](EvaluationBundle#structfield.critical_errors).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn critical_errors<T3>(
                    self,
                    value: T3,
                ) -> EvaluationBundleBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::CriticalErrorCondition>]>,
                    >,
                {
                    let (v0, v1, v2) = self.0;
                    EvaluationBundleBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> EvaluationBundleBuilder<(T0, T1, T2, T3)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [EvaluationBundle].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationBundle>
                where
                    Self: ::planus::WriteAsOffset<EvaluationBundle>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::EvaluationCase>]>>,
                    T2: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::MetricSpec>]>>,
                    T3: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::CriticalErrorCondition>]>,
                    >,
                > ::planus::WriteAs<::planus::Offset<EvaluationBundle>>
                for EvaluationBundleBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<EvaluationBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::EvaluationCase>]>>,
                    T2: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::MetricSpec>]>>,
                    T3: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::CriticalErrorCondition>]>,
                    >,
                > ::planus::WriteAsOptional<::planus::Offset<EvaluationBundle>>
                for EvaluationBundleBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<EvaluationBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<EvaluationBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::EvaluationCase>]>>,
                    T2: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::MetricSpec>]>>,
                    T3: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::CriticalErrorCondition>]>,
                    >,
                > ::planus::WriteAsOffset<EvaluationBundle>
                for EvaluationBundleBuilder<(T0, T1, T2, T3)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<EvaluationBundle> {
                    let (v0, v1, v2, v3) = &self.0;
                    EvaluationBundle::create(builder, v0, v1, v2, v3)
                }
            }

            /// Reference to a deserialized [EvaluationBundle].
            #[derive(Copy, Clone)]
            pub struct EvaluationBundleRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> EvaluationBundleRef<'a> {
                /// Getter for the [`schema_version` field](EvaluationBundle#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "EvaluationBundle", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`cases` field](EvaluationBundle#structfield.cases).
                #[inline]
                pub fn cases(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::EvaluationCaseRef<'a>>>,
                > {
                    self.0.access_required(1, "EvaluationBundle", "cases")
                }

                /// Getter for the [`metrics` field](EvaluationBundle#structfield.metrics).
                #[inline]
                pub fn metrics(
                    &self,
                ) -> ::planus::Result<::planus::Vector<'a, ::planus::Result<self::MetricSpecRef<'a>>>>
                {
                    self.0.access_required(2, "EvaluationBundle", "metrics")
                }

                /// Getter for the [`critical_errors` field](EvaluationBundle#structfield.critical_errors).
                #[inline]
                pub fn critical_errors(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::CriticalErrorConditionRef<'a>>>,
                > {
                    self.0
                        .access_required(3, "EvaluationBundle", "critical_errors")
                }
            }

            impl<'a> ::core::fmt::Debug for EvaluationBundleRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("EvaluationBundleRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("cases", &self.cases());
                    f.field("metrics", &self.metrics());
                    f.field("critical_errors", &self.critical_errors());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<EvaluationBundleRef<'a>> for EvaluationBundle {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: EvaluationBundleRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        cases: value.cases()?.to_vec_result()?,
                        metrics: value.metrics()?.to_vec_result()?,
                        critical_errors: value.critical_errors()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for EvaluationBundleRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for EvaluationBundleRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[EvaluationBundleRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<EvaluationBundle>> for EvaluationBundle {
                type Value = ::planus::Offset<EvaluationBundle>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<EvaluationBundle>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for EvaluationBundleRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[EvaluationBundleRef]", "read_as_root", 0)
                    })
                }
            }

            /// The enum `NodeKind` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Enum `NodeKind` in the file `schemas\flatbuffers\execution.fbs:5`
            #[derive(
                Copy,
                Clone,
                Debug,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            #[repr(u8)]
            pub enum NodeKind {
                /// The variant `ReadInput` in the enum `NodeKind`
                ReadInput = 0,

                /// The variant `Normalize` in the enum `NodeKind`
                Normalize = 1,

                /// The variant `Lookup` in the enum `NodeKind`
                Lookup = 2,

                /// The variant `Retrieve` in the enum `NodeKind`
                Retrieve = 3,

                /// The variant `RuleEval` in the enum `NodeKind`
                RuleEval = 4,

                /// The variant `NativeCall` in the enum `NodeKind`
                NativeCall = 5,

                /// The variant `ModelCall` in the enum `NodeKind`
                ModelCall = 6,

                /// The variant `Parallel` in the enum `NodeKind`
                Parallel = 7,

                /// The variant `Join` in the enum `NodeKind`
                Join = 8,

                /// The variant `Branch` in the enum `NodeKind`
                Branch = 9,

                /// The variant `LoopBounded` in the enum `NodeKind`
                LoopBounded = 10,

                /// The variant `Validate` in the enum `NodeKind`
                Validate = 11,

                /// The variant `PolicyGate` in the enum `NodeKind`
                PolicyGate = 12,

                /// The variant `HumanReview` in the enum `NodeKind`
                HumanReview = 13,

                /// The variant `Return` in the enum `NodeKind`
                Return = 14,
            }

            impl NodeKind {
                /// Array containing all valid variants of NodeKind
                pub const ENUM_VALUES: [Self; 15] = [
                    Self::ReadInput,
                    Self::Normalize,
                    Self::Lookup,
                    Self::Retrieve,
                    Self::RuleEval,
                    Self::NativeCall,
                    Self::ModelCall,
                    Self::Parallel,
                    Self::Join,
                    Self::Branch,
                    Self::LoopBounded,
                    Self::Validate,
                    Self::PolicyGate,
                    Self::HumanReview,
                    Self::Return,
                ];
            }

            impl ::core::convert::TryFrom<u8> for NodeKind {
                type Error = ::planus::errors::UnknownEnumTagKind;
                #[inline]
                fn try_from(
                    value: u8,
                ) -> ::core::result::Result<Self, ::planus::errors::UnknownEnumTagKind>
                {
                    #[allow(clippy::match_single_binding)]
                    match value {
                        0 => ::core::result::Result::Ok(NodeKind::ReadInput),
                        1 => ::core::result::Result::Ok(NodeKind::Normalize),
                        2 => ::core::result::Result::Ok(NodeKind::Lookup),
                        3 => ::core::result::Result::Ok(NodeKind::Retrieve),
                        4 => ::core::result::Result::Ok(NodeKind::RuleEval),
                        5 => ::core::result::Result::Ok(NodeKind::NativeCall),
                        6 => ::core::result::Result::Ok(NodeKind::ModelCall),
                        7 => ::core::result::Result::Ok(NodeKind::Parallel),
                        8 => ::core::result::Result::Ok(NodeKind::Join),
                        9 => ::core::result::Result::Ok(NodeKind::Branch),
                        10 => ::core::result::Result::Ok(NodeKind::LoopBounded),
                        11 => ::core::result::Result::Ok(NodeKind::Validate),
                        12 => ::core::result::Result::Ok(NodeKind::PolicyGate),
                        13 => ::core::result::Result::Ok(NodeKind::HumanReview),
                        14 => ::core::result::Result::Ok(NodeKind::Return),

                        _ => ::core::result::Result::Err(::planus::errors::UnknownEnumTagKind {
                            tag: value as i128,
                        }),
                    }
                }
            }

            impl ::core::convert::From<NodeKind> for u8 {
                #[inline]
                fn from(value: NodeKind) -> Self {
                    value as u8
                }
            }

            /// # Safety
            /// The Planus compiler correctly calculates `ALIGNMENT` and `SIZE`.
            unsafe impl ::planus::Primitive for NodeKind {
                const ALIGNMENT: usize = 1;
                const SIZE: usize = 1;
            }

            impl ::planus::WriteAsPrimitive<NodeKind> for NodeKind {
                #[inline]
                fn write<const N: usize>(
                    &self,
                    cursor: ::planus::Cursor<'_, N>,
                    buffer_position: u32,
                ) {
                    (*self as u8).write(cursor, buffer_position);
                }
            }

            impl ::planus::WriteAs<NodeKind> for NodeKind {
                type Prepared = Self;

                #[inline]
                fn prepare(&self, _builder: &mut ::planus::Builder) -> NodeKind {
                    *self
                }
            }

            impl ::planus::WriteAsDefault<NodeKind, NodeKind> for NodeKind {
                type Prepared = Self;

                #[inline]
                fn prepare(
                    &self,
                    _builder: &mut ::planus::Builder,
                    default: &NodeKind,
                ) -> ::core::option::Option<NodeKind> {
                    if self == default {
                        ::core::option::Option::None
                    } else {
                        ::core::option::Option::Some(*self)
                    }
                }
            }

            impl ::planus::WriteAsOptional<NodeKind> for NodeKind {
                type Prepared = Self;

                #[inline]
                fn prepare(
                    &self,
                    _builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<NodeKind> {
                    ::core::option::Option::Some(*self)
                }
            }

            impl<'buf> ::planus::TableRead<'buf> for NodeKind {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'buf>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    let n: u8 = ::planus::TableRead::from_buffer(buffer, offset)?;
                    ::core::result::Result::Ok(::core::convert::TryInto::try_into(n)?)
                }
            }

            impl<'buf> ::planus::VectorReadInner<'buf> for NodeKind {
                type Error = ::planus::errors::UnknownEnumTag;
                const STRIDE: usize = 1;
                #[inline]
                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'buf>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::UnknownEnumTag>
                {
                    let value = unsafe { *buffer.buffer.get_unchecked(offset) };
                    let value: ::core::result::Result<Self, _> =
                        ::core::convert::TryInto::try_into(value);
                    value.map_err(|error_kind| {
                        error_kind.with_error_location(
                            "NodeKind",
                            "VectorRead::from_buffer",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<NodeKind> for NodeKind {
                const STRIDE: usize = 1;

                type Value = Self;

                #[inline]
                fn prepare(&self, _builder: &mut ::planus::Builder) -> Self {
                    *self
                }

                #[inline]
                unsafe fn write_values(
                    values: &[Self],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 1];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - i as u32,
                        );
                    }
                }
            }

            /// The enum `EdgeKind` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Enum `EdgeKind` in the file `schemas\flatbuffers\execution.fbs:23`
            #[derive(
                Copy,
                Clone,
                Debug,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            #[repr(u8)]
            pub enum EdgeKind {
                /// The variant `Success` in the enum `EdgeKind`
                Success = 0,

                /// The variant `Failure` in the enum `EdgeKind`
                Failure = 1,

                /// The variant `BranchTrue` in the enum `EdgeKind`
                BranchTrue = 2,

                /// The variant `BranchFalse` in the enum `EdgeKind`
                BranchFalse = 3,

                /// The variant `Parallel` in the enum `EdgeKind`
                Parallel = 4,

                /// The variant `Join` in the enum `EdgeKind`
                Join = 5,
            }

            impl EdgeKind {
                /// Array containing all valid variants of EdgeKind
                pub const ENUM_VALUES: [Self; 6] = [
                    Self::Success,
                    Self::Failure,
                    Self::BranchTrue,
                    Self::BranchFalse,
                    Self::Parallel,
                    Self::Join,
                ];
            }

            impl ::core::convert::TryFrom<u8> for EdgeKind {
                type Error = ::planus::errors::UnknownEnumTagKind;
                #[inline]
                fn try_from(
                    value: u8,
                ) -> ::core::result::Result<Self, ::planus::errors::UnknownEnumTagKind>
                {
                    #[allow(clippy::match_single_binding)]
                    match value {
                        0 => ::core::result::Result::Ok(EdgeKind::Success),
                        1 => ::core::result::Result::Ok(EdgeKind::Failure),
                        2 => ::core::result::Result::Ok(EdgeKind::BranchTrue),
                        3 => ::core::result::Result::Ok(EdgeKind::BranchFalse),
                        4 => ::core::result::Result::Ok(EdgeKind::Parallel),
                        5 => ::core::result::Result::Ok(EdgeKind::Join),

                        _ => ::core::result::Result::Err(::planus::errors::UnknownEnumTagKind {
                            tag: value as i128,
                        }),
                    }
                }
            }

            impl ::core::convert::From<EdgeKind> for u8 {
                #[inline]
                fn from(value: EdgeKind) -> Self {
                    value as u8
                }
            }

            /// # Safety
            /// The Planus compiler correctly calculates `ALIGNMENT` and `SIZE`.
            unsafe impl ::planus::Primitive for EdgeKind {
                const ALIGNMENT: usize = 1;
                const SIZE: usize = 1;
            }

            impl ::planus::WriteAsPrimitive<EdgeKind> for EdgeKind {
                #[inline]
                fn write<const N: usize>(
                    &self,
                    cursor: ::planus::Cursor<'_, N>,
                    buffer_position: u32,
                ) {
                    (*self as u8).write(cursor, buffer_position);
                }
            }

            impl ::planus::WriteAs<EdgeKind> for EdgeKind {
                type Prepared = Self;

                #[inline]
                fn prepare(&self, _builder: &mut ::planus::Builder) -> EdgeKind {
                    *self
                }
            }

            impl ::planus::WriteAsDefault<EdgeKind, EdgeKind> for EdgeKind {
                type Prepared = Self;

                #[inline]
                fn prepare(
                    &self,
                    _builder: &mut ::planus::Builder,
                    default: &EdgeKind,
                ) -> ::core::option::Option<EdgeKind> {
                    if self == default {
                        ::core::option::Option::None
                    } else {
                        ::core::option::Option::Some(*self)
                    }
                }
            }

            impl ::planus::WriteAsOptional<EdgeKind> for EdgeKind {
                type Prepared = Self;

                #[inline]
                fn prepare(
                    &self,
                    _builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<EdgeKind> {
                    ::core::option::Option::Some(*self)
                }
            }

            impl<'buf> ::planus::TableRead<'buf> for EdgeKind {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'buf>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    let n: u8 = ::planus::TableRead::from_buffer(buffer, offset)?;
                    ::core::result::Result::Ok(::core::convert::TryInto::try_into(n)?)
                }
            }

            impl<'buf> ::planus::VectorReadInner<'buf> for EdgeKind {
                type Error = ::planus::errors::UnknownEnumTag;
                const STRIDE: usize = 1;
                #[inline]
                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'buf>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::UnknownEnumTag>
                {
                    let value = unsafe { *buffer.buffer.get_unchecked(offset) };
                    let value: ::core::result::Result<Self, _> =
                        ::core::convert::TryInto::try_into(value);
                    value.map_err(|error_kind| {
                        error_kind.with_error_location(
                            "EdgeKind",
                            "VectorRead::from_buffer",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<EdgeKind> for EdgeKind {
                const STRIDE: usize = 1;

                type Value = Self;

                #[inline]
                fn prepare(&self, _builder: &mut ::planus::Builder) -> Self {
                    *self
                }

                #[inline]
                unsafe fn write_values(
                    values: &[Self],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 1];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - i as u32,
                        );
                    }
                }
            }

            /// The table `ExecutionNode` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `ExecutionNode` in the file `schemas\flatbuffers\execution.fbs:32`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct ExecutionNode {
                /// The field `id` in the table `ExecutionNode`
                pub id: ::planus::alloc::string::String,
                /// The field `kind` in the table `ExecutionNode`
                pub kind: self::NodeKind,
                /// The field `input_type` in the table `ExecutionNode`
                pub input_type: ::planus::alloc::string::String,
                /// The field `output_type` in the table `ExecutionNode`
                pub output_type: ::planus::alloc::string::String,
                /// The field `timeout_ms` in the table `ExecutionNode`
                pub timeout_ms: u32,
                /// The field `expected_memory_bytes` in the table `ExecutionNode`
                pub expected_memory_bytes: u64,
                /// The field `executor_id` in the table `ExecutionNode`
                pub executor_id: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `min_confidence` in the table `ExecutionNode`
                pub min_confidence: f64,
                /// The field `failure_target` in the table `ExecutionNode`
                pub failure_target: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `retry_limit` in the table `ExecutionNode`
                pub retry_limit: u32,
                /// The field `cacheable` in the table `ExecutionNode`
                pub cacheable: bool,
                /// The field `side_effect` in the table `ExecutionNode`
                pub side_effect: bool,
                /// The field `parallel_group` in the table `ExecutionNode`
                pub parallel_group: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `evidence_required` in the table `ExecutionNode`
                pub evidence_required: bool,
                /// The field `loop_max_iterations` in the table `ExecutionNode`
                pub loop_max_iterations: u32,
                /// The field `provenance_id` in the table `ExecutionNode`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for ExecutionNode {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        kind: self::NodeKind::ReadInput,
                        input_type: ::core::default::Default::default(),
                        output_type: ::core::default::Default::default(),
                        timeout_ms: 0,
                        expected_memory_bytes: 0,
                        executor_id: ::core::default::Default::default(),
                        min_confidence: 0.0,
                        failure_target: ::core::default::Default::default(),
                        retry_limit: 0,
                        cacheable: false,
                        side_effect: false,
                        parallel_group: ::core::default::Default::default(),
                        evidence_required: false,
                        loop_max_iterations: 0,
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl ExecutionNode {
                /// Creates a [ExecutionNodeBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ExecutionNodeBuilder<()> {
                    ExecutionNodeBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_kind: impl ::planus::WriteAsDefault<self::NodeKind, self::NodeKind>,
                    field_input_type: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_output_type: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_timeout_ms: impl ::planus::WriteAsDefault<u32, u32>,
                    field_expected_memory_bytes: impl ::planus::WriteAsDefault<u64, u64>,
                    field_executor_id: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_min_confidence: impl ::planus::WriteAsDefault<f64, f64>,
                    field_failure_target: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_retry_limit: impl ::planus::WriteAsDefault<u32, u32>,
                    field_cacheable: impl ::planus::WriteAsDefault<bool, bool>,
                    field_side_effect: impl ::planus::WriteAsDefault<bool, bool>,
                    field_parallel_group: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_evidence_required: impl ::planus::WriteAsDefault<bool, bool>,
                    field_loop_max_iterations: impl ::planus::WriteAsDefault<u32, u32>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_kind = field_kind.prepare(builder, &self::NodeKind::ReadInput);
                    let prepared_input_type = field_input_type.prepare(builder);
                    let prepared_output_type = field_output_type.prepare(builder);
                    let prepared_timeout_ms = field_timeout_ms.prepare(builder, &0);
                    let prepared_expected_memory_bytes =
                        field_expected_memory_bytes.prepare(builder, &0);
                    let prepared_executor_id = field_executor_id.prepare(builder);
                    let prepared_min_confidence = field_min_confidence.prepare(builder, &0.0);
                    let prepared_failure_target = field_failure_target.prepare(builder);
                    let prepared_retry_limit = field_retry_limit.prepare(builder, &0);
                    let prepared_cacheable = field_cacheable.prepare(builder, &false);
                    let prepared_side_effect = field_side_effect.prepare(builder, &false);
                    let prepared_parallel_group = field_parallel_group.prepare(builder);
                    let prepared_evidence_required =
                        field_evidence_required.prepare(builder, &false);
                    let prepared_loop_max_iterations =
                        field_loop_max_iterations.prepare(builder, &0);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<36> =
                        ::core::default::Default::default();
                    if prepared_expected_memory_bytes.is_some() {
                        table_writer.write_entry::<u64>(5);
                    }
                    if prepared_min_confidence.is_some() {
                        table_writer.write_entry::<f64>(7);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    if prepared_timeout_ms.is_some() {
                        table_writer.write_entry::<u32>(4);
                    }
                    if prepared_executor_id.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(6);
                    }
                    if prepared_failure_target.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(8);
                    }
                    if prepared_retry_limit.is_some() {
                        table_writer.write_entry::<u32>(9);
                    }
                    if prepared_parallel_group.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(12);
                    }
                    if prepared_loop_max_iterations.is_some() {
                        table_writer.write_entry::<u32>(14);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(15);
                    if prepared_kind.is_some() {
                        table_writer.write_entry::<self::NodeKind>(1);
                    }
                    if prepared_cacheable.is_some() {
                        table_writer.write_entry::<bool>(10);
                    }
                    if prepared_side_effect.is_some() {
                        table_writer.write_entry::<bool>(11);
                    }
                    if prepared_evidence_required.is_some() {
                        table_writer.write_entry::<bool>(13);
                    }

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_expected_memory_bytes) =
                                prepared_expected_memory_bytes
                            {
                                object_writer.write::<_, _, 8>(&prepared_expected_memory_bytes);
                            }
                            if let ::core::option::Option::Some(prepared_min_confidence) =
                                prepared_min_confidence
                            {
                                object_writer.write::<_, _, 8>(&prepared_min_confidence);
                            }
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_input_type);
                            object_writer.write::<_, _, 4>(&prepared_output_type);
                            if let ::core::option::Option::Some(prepared_timeout_ms) =
                                prepared_timeout_ms
                            {
                                object_writer.write::<_, _, 4>(&prepared_timeout_ms);
                            }
                            if let ::core::option::Option::Some(prepared_executor_id) =
                                prepared_executor_id
                            {
                                object_writer.write::<_, _, 4>(&prepared_executor_id);
                            }
                            if let ::core::option::Option::Some(prepared_failure_target) =
                                prepared_failure_target
                            {
                                object_writer.write::<_, _, 4>(&prepared_failure_target);
                            }
                            if let ::core::option::Option::Some(prepared_retry_limit) =
                                prepared_retry_limit
                            {
                                object_writer.write::<_, _, 4>(&prepared_retry_limit);
                            }
                            if let ::core::option::Option::Some(prepared_parallel_group) =
                                prepared_parallel_group
                            {
                                object_writer.write::<_, _, 4>(&prepared_parallel_group);
                            }
                            if let ::core::option::Option::Some(prepared_loop_max_iterations) =
                                prepared_loop_max_iterations
                            {
                                object_writer.write::<_, _, 4>(&prepared_loop_max_iterations);
                            }
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                            if let ::core::option::Option::Some(prepared_kind) = prepared_kind {
                                object_writer.write::<_, _, 1>(&prepared_kind);
                            }
                            if let ::core::option::Option::Some(prepared_cacheable) =
                                prepared_cacheable
                            {
                                object_writer.write::<_, _, 1>(&prepared_cacheable);
                            }
                            if let ::core::option::Option::Some(prepared_side_effect) =
                                prepared_side_effect
                            {
                                object_writer.write::<_, _, 1>(&prepared_side_effect);
                            }
                            if let ::core::option::Option::Some(prepared_evidence_required) =
                                prepared_evidence_required
                            {
                                object_writer.write::<_, _, 1>(&prepared_evidence_required);
                            }
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<ExecutionNode>> for ExecutionNode {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionNode> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<ExecutionNode>> for ExecutionNode {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionNode>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<ExecutionNode> for ExecutionNode {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionNode> {
                    ExecutionNode::create(
                        builder,
                        &self.id,
                        self.kind,
                        &self.input_type,
                        &self.output_type,
                        self.timeout_ms,
                        self.expected_memory_bytes,
                        &self.executor_id,
                        self.min_confidence,
                        &self.failure_target,
                        self.retry_limit,
                        self.cacheable,
                        self.side_effect,
                        &self.parallel_group,
                        self.evidence_required,
                        self.loop_max_iterations,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [ExecutionNode] type.
            ///
            /// Can be created using the [ExecutionNode::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ExecutionNodeBuilder<State>(State);

            impl ExecutionNodeBuilder<()> {
                /// Setter for the [`id` field](ExecutionNode#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> ExecutionNodeBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    ExecutionNodeBuilder((value,))
                }
            }

            impl<T0> ExecutionNodeBuilder<(T0,)> {
                /// Setter for the [`kind` field](ExecutionNode#structfield.kind).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn kind<T1>(self, value: T1) -> ExecutionNodeBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAsDefault<self::NodeKind, self::NodeKind>,
                {
                    let (v0,) = self.0;
                    ExecutionNodeBuilder((v0, value))
                }

                /// Sets the [`kind` field](ExecutionNode#structfield.kind) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn kind_as_default(self) -> ExecutionNodeBuilder<(T0, ::planus::DefaultValue)> {
                    self.kind(::planus::DefaultValue)
                }
            }

            impl<T0, T1> ExecutionNodeBuilder<(T0, T1)> {
                /// Setter for the [`input_type` field](ExecutionNode#structfield.input_type).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn input_type<T2>(self, value: T2) -> ExecutionNodeBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    ExecutionNodeBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> ExecutionNodeBuilder<(T0, T1, T2)> {
                /// Setter for the [`output_type` field](ExecutionNode#structfield.output_type).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn output_type<T3>(self, value: T3) -> ExecutionNodeBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> ExecutionNodeBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`timeout_ms` field](ExecutionNode#structfield.timeout_ms).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn timeout_ms<T4>(self, value: T4) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAsDefault<u32, u32>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, value))
                }

                /// Sets the [`timeout_ms` field](ExecutionNode#structfield.timeout_ms) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn timeout_ms_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, ::planus::DefaultValue)>
                {
                    self.timeout_ms(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4> ExecutionNodeBuilder<(T0, T1, T2, T3, T4)> {
                /// Setter for the [`expected_memory_bytes` field](ExecutionNode#structfield.expected_memory_bytes).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn expected_memory_bytes<T5>(
                    self,
                    value: T5,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5)>
                where
                    T5: ::planus::WriteAsDefault<u64, u64>,
                {
                    let (v0, v1, v2, v3, v4) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, value))
                }

                /// Sets the [`expected_memory_bytes` field](ExecutionNode#structfield.expected_memory_bytes) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn expected_memory_bytes_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, ::planus::DefaultValue)>
                {
                    self.expected_memory_bytes(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5)> {
                /// Setter for the [`executor_id` field](ExecutionNode#structfield.executor_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn executor_id<T6>(
                    self,
                    value: T6,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6)>
                where
                    T6: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2, v3, v4, v5) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, value))
                }

                /// Sets the [`executor_id` field](ExecutionNode#structfield.executor_id) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn executor_id_as_null(
                    self,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, ())> {
                    self.executor_id(())
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6)> {
                /// Setter for the [`min_confidence` field](ExecutionNode#structfield.min_confidence).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn min_confidence<T7>(
                    self,
                    value: T7,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)>
                where
                    T7: ::planus::WriteAsDefault<f64, f64>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, v6, value))
                }

                /// Sets the [`min_confidence` field](ExecutionNode#structfield.min_confidence) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn min_confidence_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, ::planus::DefaultValue)>
                {
                    self.min_confidence(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)> {
                /// Setter for the [`failure_target` field](ExecutionNode#structfield.failure_target).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn failure_target<T8>(
                    self,
                    value: T8,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)>
                where
                    T8: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, v6, v7, value))
                }

                /// Sets the [`failure_target` field](ExecutionNode#structfield.failure_target) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn failure_target_as_null(
                    self,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, ())> {
                    self.failure_target(())
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8>
                ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)>
            {
                /// Setter for the [`retry_limit` field](ExecutionNode#structfield.retry_limit).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn retry_limit<T9>(
                    self,
                    value: T9,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
                where
                    T9: ::planus::WriteAsDefault<u32, u32>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, value))
                }

                /// Sets the [`retry_limit` field](ExecutionNode#structfield.retry_limit) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn retry_limit_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    ::planus::DefaultValue,
                )> {
                    self.retry_limit(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9>
                ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
            {
                /// Setter for the [`cacheable` field](ExecutionNode#structfield.cacheable).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn cacheable<T10>(
                    self,
                    value: T10,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
                where
                    T10: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, value))
                }

                /// Sets the [`cacheable` field](ExecutionNode#structfield.cacheable) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn cacheable_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    ::planus::DefaultValue,
                )> {
                    self.cacheable(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>
                ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
            {
                /// Setter for the [`side_effect` field](ExecutionNode#structfield.side_effect).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn side_effect<T11>(
                    self,
                    value: T11,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
                where
                    T11: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, value))
                }

                /// Sets the [`side_effect` field](ExecutionNode#structfield.side_effect) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn side_effect_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    ::planus::DefaultValue,
                )> {
                    self.side_effect(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>
                ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
            {
                /// Setter for the [`parallel_group` field](ExecutionNode#structfield.parallel_group).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn parallel_group<T12>(
                    self,
                    value: T12,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
                where
                    T12: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) = self.0;
                    ExecutionNodeBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, value))
                }

                /// Sets the [`parallel_group` field](ExecutionNode#structfield.parallel_group) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn parallel_group_as_null(
                    self,
                ) -> ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, ())>
                {
                    self.parallel_group(())
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>
                ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                /// Setter for the [`evidence_required` field](ExecutionNode#structfield.evidence_required).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn evidence_required<T13>(
                    self,
                    value: T13,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                )>
                where
                    T13: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) = self.0;
                    ExecutionNodeBuilder((
                        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, value,
                    ))
                }

                /// Sets the [`evidence_required` field](ExecutionNode#structfield.evidence_required) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn evidence_required_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    ::planus::DefaultValue,
                )> {
                    self.evidence_required(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13>
                ExecutionNodeBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13)>
            {
                /// Setter for the [`loop_max_iterations` field](ExecutionNode#structfield.loop_max_iterations).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn loop_max_iterations<T14>(
                    self,
                    value: T14,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
                where
                    T14: ::planus::WriteAsDefault<u32, u32>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13) = self.0;
                    ExecutionNodeBuilder((
                        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, value,
                    ))
                }

                /// Sets the [`loop_max_iterations` field](ExecutionNode#structfield.loop_max_iterations) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn loop_max_iterations_as_default(
                    self,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    ::planus::DefaultValue,
                )> {
                    self.loop_max_iterations(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14>
                ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                )>
            {
                /// Setter for the [`provenance_id` field](ExecutionNode#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T15>(
                    self,
                    value: T15,
                ) -> ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                    T15,
                )>
                where
                    T15: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) = self.0;
                    ExecutionNodeBuilder((
                        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, value,
                    ))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15>
                ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                    T15,
                )>
            {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [ExecutionNode].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionNode>
                where
                    Self: ::planus::WriteAsOffset<ExecutionNode>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<self::NodeKind, self::NodeKind>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAsDefault<u32, u32>,
                    T5: ::planus::WriteAsDefault<u64, u64>,
                    T6: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T7: ::planus::WriteAsDefault<f64, f64>,
                    T8: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T9: ::planus::WriteAsDefault<u32, u32>,
                    T10: ::planus::WriteAsDefault<bool, bool>,
                    T11: ::planus::WriteAsDefault<bool, bool>,
                    T12: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T13: ::planus::WriteAsDefault<bool, bool>,
                    T14: ::planus::WriteAsDefault<u32, u32>,
                    T15: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<ExecutionNode>>
                for ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                    T15,
                )>
            {
                type Prepared = ::planus::Offset<ExecutionNode>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionNode> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<self::NodeKind, self::NodeKind>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAsDefault<u32, u32>,
                    T5: ::planus::WriteAsDefault<u64, u64>,
                    T6: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T7: ::planus::WriteAsDefault<f64, f64>,
                    T8: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T9: ::planus::WriteAsDefault<u32, u32>,
                    T10: ::planus::WriteAsDefault<bool, bool>,
                    T11: ::planus::WriteAsDefault<bool, bool>,
                    T12: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T13: ::planus::WriteAsDefault<bool, bool>,
                    T14: ::planus::WriteAsDefault<u32, u32>,
                    T15: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<ExecutionNode>>
                for ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                    T15,
                )>
            {
                type Prepared = ::planus::Offset<ExecutionNode>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionNode>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<self::NodeKind, self::NodeKind>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAsDefault<u32, u32>,
                    T5: ::planus::WriteAsDefault<u64, u64>,
                    T6: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T7: ::planus::WriteAsDefault<f64, f64>,
                    T8: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T9: ::planus::WriteAsDefault<u32, u32>,
                    T10: ::planus::WriteAsDefault<bool, bool>,
                    T11: ::planus::WriteAsDefault<bool, bool>,
                    T12: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T13: ::planus::WriteAsDefault<bool, bool>,
                    T14: ::planus::WriteAsDefault<u32, u32>,
                    T15: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<ExecutionNode>
                for ExecutionNodeBuilder<(
                    T0,
                    T1,
                    T2,
                    T3,
                    T4,
                    T5,
                    T6,
                    T7,
                    T8,
                    T9,
                    T10,
                    T11,
                    T12,
                    T13,
                    T14,
                    T15,
                )>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionNode> {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) =
                        &self.0;
                    ExecutionNode::create(
                        builder, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14,
                        v15,
                    )
                }
            }

            /// Reference to a deserialized [ExecutionNode].
            #[derive(Copy, Clone)]
            pub struct ExecutionNodeRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ExecutionNodeRef<'a> {
                /// Getter for the [`id` field](ExecutionNode#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "ExecutionNode", "id")
                }

                /// Getter for the [`kind` field](ExecutionNode#structfield.kind).
                #[inline]
                pub fn kind(&self) -> ::planus::Result<self::NodeKind> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(1, "ExecutionNode", "kind")?
                            .unwrap_or(self::NodeKind::ReadInput),
                    )
                }

                /// Getter for the [`input_type` field](ExecutionNode#structfield.input_type).
                #[inline]
                pub fn input_type(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "ExecutionNode", "input_type")
                }

                /// Getter for the [`output_type` field](ExecutionNode#structfield.output_type).
                #[inline]
                pub fn output_type(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(3, "ExecutionNode", "output_type")
                }

                /// Getter for the [`timeout_ms` field](ExecutionNode#structfield.timeout_ms).
                #[inline]
                pub fn timeout_ms(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(4, "ExecutionNode", "timeout_ms")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`expected_memory_bytes` field](ExecutionNode#structfield.expected_memory_bytes).
                #[inline]
                pub fn expected_memory_bytes(&self) -> ::planus::Result<u64> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(5, "ExecutionNode", "expected_memory_bytes")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`executor_id` field](ExecutionNode#structfield.executor_id).
                #[inline]
                pub fn executor_id(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(6, "ExecutionNode", "executor_id")
                }

                /// Getter for the [`min_confidence` field](ExecutionNode#structfield.min_confidence).
                #[inline]
                pub fn min_confidence(&self) -> ::planus::Result<f64> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(7, "ExecutionNode", "min_confidence")?
                            .unwrap_or(0.0),
                    )
                }

                /// Getter for the [`failure_target` field](ExecutionNode#structfield.failure_target).
                #[inline]
                pub fn failure_target(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(8, "ExecutionNode", "failure_target")
                }

                /// Getter for the [`retry_limit` field](ExecutionNode#structfield.retry_limit).
                #[inline]
                pub fn retry_limit(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(9, "ExecutionNode", "retry_limit")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`cacheable` field](ExecutionNode#structfield.cacheable).
                #[inline]
                pub fn cacheable(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(10, "ExecutionNode", "cacheable")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`side_effect` field](ExecutionNode#structfield.side_effect).
                #[inline]
                pub fn side_effect(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(11, "ExecutionNode", "side_effect")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`parallel_group` field](ExecutionNode#structfield.parallel_group).
                #[inline]
                pub fn parallel_group(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(12, "ExecutionNode", "parallel_group")
                }

                /// Getter for the [`evidence_required` field](ExecutionNode#structfield.evidence_required).
                #[inline]
                pub fn evidence_required(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(13, "ExecutionNode", "evidence_required")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`loop_max_iterations` field](ExecutionNode#structfield.loop_max_iterations).
                #[inline]
                pub fn loop_max_iterations(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(14, "ExecutionNode", "loop_max_iterations")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`provenance_id` field](ExecutionNode#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(15, "ExecutionNode", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for ExecutionNodeRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ExecutionNodeRef");
                    f.field("id", &self.id());
                    f.field("kind", &self.kind());
                    f.field("input_type", &self.input_type());
                    f.field("output_type", &self.output_type());
                    f.field("timeout_ms", &self.timeout_ms());
                    f.field("expected_memory_bytes", &self.expected_memory_bytes());
                    if let ::core::option::Option::Some(field_executor_id) =
                        self.executor_id().transpose()
                    {
                        f.field("executor_id", &field_executor_id);
                    }
                    f.field("min_confidence", &self.min_confidence());
                    if let ::core::option::Option::Some(field_failure_target) =
                        self.failure_target().transpose()
                    {
                        f.field("failure_target", &field_failure_target);
                    }
                    f.field("retry_limit", &self.retry_limit());
                    f.field("cacheable", &self.cacheable());
                    f.field("side_effect", &self.side_effect());
                    if let ::core::option::Option::Some(field_parallel_group) =
                        self.parallel_group().transpose()
                    {
                        f.field("parallel_group", &field_parallel_group);
                    }
                    f.field("evidence_required", &self.evidence_required());
                    f.field("loop_max_iterations", &self.loop_max_iterations());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ExecutionNodeRef<'a>> for ExecutionNode {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ExecutionNodeRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        kind: ::core::convert::TryInto::try_into(value.kind()?)?,
                        input_type: ::core::convert::Into::into(value.input_type()?),
                        output_type: ::core::convert::Into::into(value.output_type()?),
                        timeout_ms: ::core::convert::TryInto::try_into(value.timeout_ms()?)?,
                        expected_memory_bytes: ::core::convert::TryInto::try_into(
                            value.expected_memory_bytes()?,
                        )?,
                        executor_id: value.executor_id()?.map(::core::convert::Into::into),
                        min_confidence: ::core::convert::TryInto::try_into(
                            value.min_confidence()?,
                        )?,
                        failure_target: value.failure_target()?.map(::core::convert::Into::into),
                        retry_limit: ::core::convert::TryInto::try_into(value.retry_limit()?)?,
                        cacheable: ::core::convert::TryInto::try_into(value.cacheable()?)?,
                        side_effect: ::core::convert::TryInto::try_into(value.side_effect()?)?,
                        parallel_group: value.parallel_group()?.map(::core::convert::Into::into),
                        evidence_required: ::core::convert::TryInto::try_into(
                            value.evidence_required()?,
                        )?,
                        loop_max_iterations: ::core::convert::TryInto::try_into(
                            value.loop_max_iterations()?,
                        )?,
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ExecutionNodeRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ExecutionNodeRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ExecutionNodeRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<ExecutionNode>> for ExecutionNode {
                type Value = ::planus::Offset<ExecutionNode>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<ExecutionNode>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ExecutionNodeRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[ExecutionNodeRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `ExecutionEdge` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `ExecutionEdge` in the file `schemas\flatbuffers\execution.fbs:51`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct ExecutionEdge {
                /// The field `from` in the table `ExecutionEdge`
                pub from: ::planus::alloc::string::String,
                /// The field `to` in the table `ExecutionEdge`
                pub to: ::planus::alloc::string::String,
                /// The field `kind` in the table `ExecutionEdge`
                pub kind: self::EdgeKind,
                /// The field `condition` in the table `ExecutionEdge`
                pub condition: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `provenance_id` in the table `ExecutionEdge`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for ExecutionEdge {
                fn default() -> Self {
                    Self {
                        from: ::core::default::Default::default(),
                        to: ::core::default::Default::default(),
                        kind: self::EdgeKind::Success,
                        condition: ::core::default::Default::default(),
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl ExecutionEdge {
                /// Creates a [ExecutionEdgeBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ExecutionEdgeBuilder<()> {
                    ExecutionEdgeBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_from: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_to: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_kind: impl ::planus::WriteAsDefault<self::EdgeKind, self::EdgeKind>,
                    field_condition: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_from = field_from.prepare(builder);
                    let prepared_to = field_to.prepare(builder);
                    let prepared_kind = field_kind.prepare(builder, &self::EdgeKind::Success);
                    let prepared_condition = field_condition.prepare(builder);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<14> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    if prepared_condition.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(3);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(4);
                    if prepared_kind.is_some() {
                        table_writer.write_entry::<self::EdgeKind>(2);
                    }

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_from);
                            object_writer.write::<_, _, 4>(&prepared_to);
                            if let ::core::option::Option::Some(prepared_condition) =
                                prepared_condition
                            {
                                object_writer.write::<_, _, 4>(&prepared_condition);
                            }
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                            if let ::core::option::Option::Some(prepared_kind) = prepared_kind {
                                object_writer.write::<_, _, 1>(&prepared_kind);
                            }
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<ExecutionEdge>> for ExecutionEdge {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionEdge> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<ExecutionEdge>> for ExecutionEdge {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionEdge>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<ExecutionEdge> for ExecutionEdge {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionEdge> {
                    ExecutionEdge::create(
                        builder,
                        &self.from,
                        &self.to,
                        self.kind,
                        &self.condition,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [ExecutionEdge] type.
            ///
            /// Can be created using the [ExecutionEdge::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ExecutionEdgeBuilder<State>(State);

            impl ExecutionEdgeBuilder<()> {
                /// Setter for the [`from` field](ExecutionEdge#structfield.from).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn from<T0>(self, value: T0) -> ExecutionEdgeBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    ExecutionEdgeBuilder((value,))
                }
            }

            impl<T0> ExecutionEdgeBuilder<(T0,)> {
                /// Setter for the [`to` field](ExecutionEdge#structfield.to).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn to<T1>(self, value: T1) -> ExecutionEdgeBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    ExecutionEdgeBuilder((v0, value))
                }
            }

            impl<T0, T1> ExecutionEdgeBuilder<(T0, T1)> {
                /// Setter for the [`kind` field](ExecutionEdge#structfield.kind).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn kind<T2>(self, value: T2) -> ExecutionEdgeBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsDefault<self::EdgeKind, self::EdgeKind>,
                {
                    let (v0, v1) = self.0;
                    ExecutionEdgeBuilder((v0, v1, value))
                }

                /// Sets the [`kind` field](ExecutionEdge#structfield.kind) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn kind_as_default(
                    self,
                ) -> ExecutionEdgeBuilder<(T0, T1, ::planus::DefaultValue)> {
                    self.kind(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2> ExecutionEdgeBuilder<(T0, T1, T2)> {
                /// Setter for the [`condition` field](ExecutionEdge#structfield.condition).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn condition<T3>(self, value: T3) -> ExecutionEdgeBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2) = self.0;
                    ExecutionEdgeBuilder((v0, v1, v2, value))
                }

                /// Sets the [`condition` field](ExecutionEdge#structfield.condition) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn condition_as_null(self) -> ExecutionEdgeBuilder<(T0, T1, T2, ())> {
                    self.condition(())
                }
            }

            impl<T0, T1, T2, T3> ExecutionEdgeBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`provenance_id` field](ExecutionEdge#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T4>(
                    self,
                    value: T4,
                ) -> ExecutionEdgeBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    ExecutionEdgeBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> ExecutionEdgeBuilder<(T0, T1, T2, T3, T4)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [ExecutionEdge].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionEdge>
                where
                    Self: ::planus::WriteAsOffset<ExecutionEdge>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<self::EdgeKind, self::EdgeKind>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<ExecutionEdge>>
                for ExecutionEdgeBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<ExecutionEdge>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionEdge> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<self::EdgeKind, self::EdgeKind>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<ExecutionEdge>>
                for ExecutionEdgeBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<ExecutionEdge>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionEdge>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<self::EdgeKind, self::EdgeKind>,
                    T3: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<ExecutionEdge>
                for ExecutionEdgeBuilder<(T0, T1, T2, T3, T4)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionEdge> {
                    let (v0, v1, v2, v3, v4) = &self.0;
                    ExecutionEdge::create(builder, v0, v1, v2, v3, v4)
                }
            }

            /// Reference to a deserialized [ExecutionEdge].
            #[derive(Copy, Clone)]
            pub struct ExecutionEdgeRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ExecutionEdgeRef<'a> {
                /// Getter for the [`from` field](ExecutionEdge#structfield.from).
                #[inline]
                pub fn from(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "ExecutionEdge", "from")
                }

                /// Getter for the [`to` field](ExecutionEdge#structfield.to).
                #[inline]
                pub fn to(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "ExecutionEdge", "to")
                }

                /// Getter for the [`kind` field](ExecutionEdge#structfield.kind).
                #[inline]
                pub fn kind(&self) -> ::planus::Result<self::EdgeKind> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(2, "ExecutionEdge", "kind")?
                            .unwrap_or(self::EdgeKind::Success),
                    )
                }

                /// Getter for the [`condition` field](ExecutionEdge#structfield.condition).
                #[inline]
                pub fn condition(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(3, "ExecutionEdge", "condition")
                }

                /// Getter for the [`provenance_id` field](ExecutionEdge#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(4, "ExecutionEdge", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for ExecutionEdgeRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ExecutionEdgeRef");
                    f.field("from", &self.from());
                    f.field("to", &self.to());
                    f.field("kind", &self.kind());
                    if let ::core::option::Option::Some(field_condition) =
                        self.condition().transpose()
                    {
                        f.field("condition", &field_condition);
                    }
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ExecutionEdgeRef<'a>> for ExecutionEdge {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ExecutionEdgeRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        from: ::core::convert::Into::into(value.from()?),
                        to: ::core::convert::Into::into(value.to()?),
                        kind: ::core::convert::TryInto::try_into(value.kind()?)?,
                        condition: value.condition()?.map(::core::convert::Into::into),
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ExecutionEdgeRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ExecutionEdgeRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ExecutionEdgeRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<ExecutionEdge>> for ExecutionEdge {
                type Value = ::planus::Offset<ExecutionEdge>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<ExecutionEdge>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ExecutionEdgeRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[ExecutionEdgeRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `ExecutionGraph` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `ExecutionGraph` in the file `schemas\flatbuffers\execution.fbs:59`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct ExecutionGraph {
                /// The field `schema_version` in the table `ExecutionGraph`
                pub schema_version: u32,
                /// The field `skill_id` in the table `ExecutionGraph`
                pub skill_id: ::planus::alloc::string::String,
                /// The field `entry_node` in the table `ExecutionGraph`
                pub entry_node: ::planus::alloc::string::String,
                /// The field `nodes` in the table `ExecutionGraph`
                pub nodes: ::planus::alloc::vec::Vec<self::ExecutionNode>,
                /// The field `edges` in the table `ExecutionGraph`
                pub edges: ::planus::alloc::vec::Vec<self::ExecutionEdge>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for ExecutionGraph {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        skill_id: ::core::default::Default::default(),
                        entry_node: ::core::default::Default::default(),
                        nodes: ::core::default::Default::default(),
                        edges: ::core::default::Default::default(),
                    }
                }
            }

            impl ExecutionGraph {
                /// Creates a [ExecutionGraphBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ExecutionGraphBuilder<()> {
                    ExecutionGraphBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_skill_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_entry_node: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_nodes: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ExecutionNode>]>,
                    >,
                    field_edges: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ExecutionEdge>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_skill_id = field_skill_id.prepare(builder);
                    let prepared_entry_node = field_entry_node.prepare(builder);
                    let prepared_nodes = field_nodes.prepare(builder);
                    let prepared_edges = field_edges.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<14> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::ExecutionNode>]>>(
                            3,
                        );
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::ExecutionEdge>]>>(
                            4,
                        );

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_skill_id);
                            object_writer.write::<_, _, 4>(&prepared_entry_node);
                            object_writer.write::<_, _, 4>(&prepared_nodes);
                            object_writer.write::<_, _, 4>(&prepared_edges);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<ExecutionGraph>> for ExecutionGraph {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionGraph> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<ExecutionGraph>> for ExecutionGraph {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionGraph>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<ExecutionGraph> for ExecutionGraph {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionGraph> {
                    ExecutionGraph::create(
                        builder,
                        self.schema_version,
                        &self.skill_id,
                        &self.entry_node,
                        &self.nodes,
                        &self.edges,
                    )
                }
            }

            /// Builder for serializing an instance of the [ExecutionGraph] type.
            ///
            /// Can be created using the [ExecutionGraph::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ExecutionGraphBuilder<State>(State);

            impl ExecutionGraphBuilder<()> {
                /// Setter for the [`schema_version` field](ExecutionGraph#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> ExecutionGraphBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    ExecutionGraphBuilder((value,))
                }

                /// Sets the [`schema_version` field](ExecutionGraph#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> ExecutionGraphBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> ExecutionGraphBuilder<(T0,)> {
                /// Setter for the [`skill_id` field](ExecutionGraph#structfield.skill_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn skill_id<T1>(self, value: T1) -> ExecutionGraphBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    ExecutionGraphBuilder((v0, value))
                }
            }

            impl<T0, T1> ExecutionGraphBuilder<(T0, T1)> {
                /// Setter for the [`entry_node` field](ExecutionGraph#structfield.entry_node).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn entry_node<T2>(self, value: T2) -> ExecutionGraphBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    ExecutionGraphBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> ExecutionGraphBuilder<(T0, T1, T2)> {
                /// Setter for the [`nodes` field](ExecutionGraph#structfield.nodes).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn nodes<T3>(self, value: T3) -> ExecutionGraphBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ExecutionNode>]>,
                    >,
                {
                    let (v0, v1, v2) = self.0;
                    ExecutionGraphBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> ExecutionGraphBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`edges` field](ExecutionGraph#structfield.edges).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn edges<T4>(self, value: T4) -> ExecutionGraphBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ExecutionEdge>]>,
                    >,
                {
                    let (v0, v1, v2, v3) = self.0;
                    ExecutionGraphBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> ExecutionGraphBuilder<(T0, T1, T2, T3, T4)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [ExecutionGraph].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionGraph>
                where
                    Self: ::planus::WriteAsOffset<ExecutionGraph>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionNode>]>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionEdge>]>>,
                > ::planus::WriteAs<::planus::Offset<ExecutionGraph>>
                for ExecutionGraphBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<ExecutionGraph>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionGraph> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionNode>]>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionEdge>]>>,
                > ::planus::WriteAsOptional<::planus::Offset<ExecutionGraph>>
                for ExecutionGraphBuilder<(T0, T1, T2, T3, T4)>
            {
                type Prepared = ::planus::Offset<ExecutionGraph>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionGraph>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionNode>]>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionEdge>]>>,
                > ::planus::WriteAsOffset<ExecutionGraph>
                for ExecutionGraphBuilder<(T0, T1, T2, T3, T4)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionGraph> {
                    let (v0, v1, v2, v3, v4) = &self.0;
                    ExecutionGraph::create(builder, v0, v1, v2, v3, v4)
                }
            }

            /// Reference to a deserialized [ExecutionGraph].
            #[derive(Copy, Clone)]
            pub struct ExecutionGraphRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ExecutionGraphRef<'a> {
                /// Getter for the [`schema_version` field](ExecutionGraph#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "ExecutionGraph", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`skill_id` field](ExecutionGraph#structfield.skill_id).
                #[inline]
                pub fn skill_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "ExecutionGraph", "skill_id")
                }

                /// Getter for the [`entry_node` field](ExecutionGraph#structfield.entry_node).
                #[inline]
                pub fn entry_node(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "ExecutionGraph", "entry_node")
                }

                /// Getter for the [`nodes` field](ExecutionGraph#structfield.nodes).
                #[inline]
                pub fn nodes(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::ExecutionNodeRef<'a>>>,
                > {
                    self.0.access_required(3, "ExecutionGraph", "nodes")
                }

                /// Getter for the [`edges` field](ExecutionGraph#structfield.edges).
                #[inline]
                pub fn edges(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::ExecutionEdgeRef<'a>>>,
                > {
                    self.0.access_required(4, "ExecutionGraph", "edges")
                }
            }

            impl<'a> ::core::fmt::Debug for ExecutionGraphRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ExecutionGraphRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("skill_id", &self.skill_id());
                    f.field("entry_node", &self.entry_node());
                    f.field("nodes", &self.nodes());
                    f.field("edges", &self.edges());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ExecutionGraphRef<'a>> for ExecutionGraph {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ExecutionGraphRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        skill_id: ::core::convert::Into::into(value.skill_id()?),
                        entry_node: ::core::convert::Into::into(value.entry_node()?),
                        nodes: value.nodes()?.to_vec_result()?,
                        edges: value.edges()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ExecutionGraphRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ExecutionGraphRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ExecutionGraphRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<ExecutionGraph>> for ExecutionGraph {
                type Value = ::planus::Offset<ExecutionGraph>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<ExecutionGraph>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ExecutionGraphRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[ExecutionGraphRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `ExecutionBundle` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `ExecutionBundle` in the file `schemas\flatbuffers\execution.fbs:67`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct ExecutionBundle {
                /// The field `schema_version` in the table `ExecutionBundle`
                pub schema_version: u32,
                /// The field `graphs` in the table `ExecutionBundle`
                pub graphs: ::planus::alloc::vec::Vec<self::ExecutionGraph>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for ExecutionBundle {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        graphs: ::core::default::Default::default(),
                    }
                }
            }

            impl ExecutionBundle {
                /// Creates a [ExecutionBundleBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ExecutionBundleBuilder<()> {
                    ExecutionBundleBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_graphs: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ExecutionGraph>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_graphs = field_graphs.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<8> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::ExecutionGraph>]>>(
                            1,
                        );

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_graphs);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<ExecutionBundle>> for ExecutionBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<ExecutionBundle>> for ExecutionBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<ExecutionBundle> for ExecutionBundle {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionBundle> {
                    ExecutionBundle::create(builder, self.schema_version, &self.graphs)
                }
            }

            /// Builder for serializing an instance of the [ExecutionBundle] type.
            ///
            /// Can be created using the [ExecutionBundle::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ExecutionBundleBuilder<State>(State);

            impl ExecutionBundleBuilder<()> {
                /// Setter for the [`schema_version` field](ExecutionBundle#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> ExecutionBundleBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    ExecutionBundleBuilder((value,))
                }

                /// Sets the [`schema_version` field](ExecutionBundle#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> ExecutionBundleBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> ExecutionBundleBuilder<(T0,)> {
                /// Setter for the [`graphs` field](ExecutionBundle#structfield.graphs).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn graphs<T1>(self, value: T1) -> ExecutionBundleBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ExecutionGraph>]>,
                    >,
                {
                    let (v0,) = self.0;
                    ExecutionBundleBuilder((v0, value))
                }
            }

            impl<T0, T1> ExecutionBundleBuilder<(T0, T1)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [ExecutionBundle].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionBundle>
                where
                    Self: ::planus::WriteAsOffset<ExecutionBundle>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionGraph>]>>,
                > ::planus::WriteAs<::planus::Offset<ExecutionBundle>>
                for ExecutionBundleBuilder<(T0, T1)>
            {
                type Prepared = ::planus::Offset<ExecutionBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionGraph>]>>,
                > ::planus::WriteAsOptional<::planus::Offset<ExecutionBundle>>
                for ExecutionBundleBuilder<(T0, T1)>
            {
                type Prepared = ::planus::Offset<ExecutionBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ExecutionBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ExecutionGraph>]>>,
                > ::planus::WriteAsOffset<ExecutionBundle> for ExecutionBundleBuilder<(T0, T1)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ExecutionBundle> {
                    let (v0, v1) = &self.0;
                    ExecutionBundle::create(builder, v0, v1)
                }
            }

            /// Reference to a deserialized [ExecutionBundle].
            #[derive(Copy, Clone)]
            pub struct ExecutionBundleRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ExecutionBundleRef<'a> {
                /// Getter for the [`schema_version` field](ExecutionBundle#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "ExecutionBundle", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`graphs` field](ExecutionBundle#structfield.graphs).
                #[inline]
                pub fn graphs(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::ExecutionGraphRef<'a>>>,
                > {
                    self.0.access_required(1, "ExecutionBundle", "graphs")
                }
            }

            impl<'a> ::core::fmt::Debug for ExecutionBundleRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ExecutionBundleRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("graphs", &self.graphs());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ExecutionBundleRef<'a>> for ExecutionBundle {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ExecutionBundleRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        graphs: value.graphs()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ExecutionBundleRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ExecutionBundleRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ExecutionBundleRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<ExecutionBundle>> for ExecutionBundle {
                type Value = ::planus::Offset<ExecutionBundle>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<ExecutionBundle>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ExecutionBundleRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[ExecutionBundleRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `PackageFile` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `PackageFile` in the file `schemas\flatbuffers\manifest.fbs:5`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct PackageFile {
                /// The field `path` in the table `PackageFile`
                pub path: ::planus::alloc::string::String,
                /// The field `size` in the table `PackageFile`
                pub size: u64,
                /// The field `content_hash` in the table `PackageFile`
                pub content_hash: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for PackageFile {
                fn default() -> Self {
                    Self {
                        path: ::core::default::Default::default(),
                        size: 0,
                        content_hash: ::core::default::Default::default(),
                    }
                }
            }

            impl PackageFile {
                /// Creates a [PackageFileBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> PackageFileBuilder<()> {
                    PackageFileBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_path: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_size: impl ::planus::WriteAsDefault<u64, u64>,
                    field_content_hash: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_path = field_path.prepare(builder);
                    let prepared_size = field_size.prepare(builder, &0);
                    let prepared_content_hash = field_content_hash.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<10> =
                        ::core::default::Default::default();
                    if prepared_size.is_some() {
                        table_writer.write_entry::<u64>(1);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(2);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_size) = prepared_size {
                                object_writer.write::<_, _, 8>(&prepared_size);
                            }
                            object_writer.write::<_, _, 4>(&prepared_path);
                            object_writer.write::<_, _, 4>(&prepared_content_hash);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<PackageFile>> for PackageFile {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageFile> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<PackageFile>> for PackageFile {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<PackageFile>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<PackageFile> for PackageFile {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageFile> {
                    PackageFile::create(builder, &self.path, self.size, &self.content_hash)
                }
            }

            /// Builder for serializing an instance of the [PackageFile] type.
            ///
            /// Can be created using the [PackageFile::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct PackageFileBuilder<State>(State);

            impl PackageFileBuilder<()> {
                /// Setter for the [`path` field](PackageFile#structfield.path).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn path<T0>(self, value: T0) -> PackageFileBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    PackageFileBuilder((value,))
                }
            }

            impl<T0> PackageFileBuilder<(T0,)> {
                /// Setter for the [`size` field](PackageFile#structfield.size).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn size<T1>(self, value: T1) -> PackageFileBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAsDefault<u64, u64>,
                {
                    let (v0,) = self.0;
                    PackageFileBuilder((v0, value))
                }

                /// Sets the [`size` field](PackageFile#structfield.size) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn size_as_default(self) -> PackageFileBuilder<(T0, ::planus::DefaultValue)> {
                    self.size(::planus::DefaultValue)
                }
            }

            impl<T0, T1> PackageFileBuilder<(T0, T1)> {
                /// Setter for the [`content_hash` field](PackageFile#structfield.content_hash).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn content_hash<T2>(self, value: T2) -> PackageFileBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    PackageFileBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> PackageFileBuilder<(T0, T1, T2)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [PackageFile].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageFile>
                where
                    Self: ::planus::WriteAsOffset<PackageFile>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<u64, u64>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<PackageFile>>
                for PackageFileBuilder<(T0, T1, T2)>
            {
                type Prepared = ::planus::Offset<PackageFile>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageFile> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<u64, u64>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<PackageFile>>
                for PackageFileBuilder<(T0, T1, T2)>
            {
                type Prepared = ::planus::Offset<PackageFile>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<PackageFile>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<u64, u64>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<PackageFile> for PackageFileBuilder<(T0, T1, T2)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageFile> {
                    let (v0, v1, v2) = &self.0;
                    PackageFile::create(builder, v0, v1, v2)
                }
            }

            /// Reference to a deserialized [PackageFile].
            #[derive(Copy, Clone)]
            pub struct PackageFileRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> PackageFileRef<'a> {
                /// Getter for the [`path` field](PackageFile#structfield.path).
                #[inline]
                pub fn path(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "PackageFile", "path")
                }

                /// Getter for the [`size` field](PackageFile#structfield.size).
                #[inline]
                pub fn size(&self) -> ::planus::Result<u64> {
                    ::core::result::Result::Ok(
                        self.0.access(1, "PackageFile", "size")?.unwrap_or(0),
                    )
                }

                /// Getter for the [`content_hash` field](PackageFile#structfield.content_hash).
                #[inline]
                pub fn content_hash(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "PackageFile", "content_hash")
                }
            }

            impl<'a> ::core::fmt::Debug for PackageFileRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("PackageFileRef");
                    f.field("path", &self.path());
                    f.field("size", &self.size());
                    f.field("content_hash", &self.content_hash());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<PackageFileRef<'a>> for PackageFile {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: PackageFileRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        path: ::core::convert::Into::into(value.path()?),
                        size: ::core::convert::TryInto::try_into(value.size()?)?,
                        content_hash: ::core::convert::Into::into(value.content_hash()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for PackageFileRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for PackageFileRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[PackageFileRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<PackageFile>> for PackageFile {
                type Value = ::planus::Offset<PackageFile>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<PackageFile>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for PackageFileRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[PackageFileRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `PackageManifest` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `PackageManifest` in the file `schemas\flatbuffers\manifest.fbs:11`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct PackageManifest {
                /// The field `schema_version` in the table `PackageManifest`
                pub schema_version: u32,
                /// The field `package_format_version` in the table `PackageManifest`
                pub package_format_version: ::planus::alloc::string::String,
                /// The field `compiler_version` in the table `PackageManifest`
                pub compiler_version: ::planus::alloc::string::String,
                /// The field `runtime_abi_version` in the table `PackageManifest`
                pub runtime_abi_version: ::planus::alloc::string::String,
                /// The field `domain_id` in the table `PackageManifest`
                pub domain_id: ::planus::alloc::string::String,
                /// The field `domain_version` in the table `PackageManifest`
                pub domain_version: ::planus::alloc::string::String,
                /// The field `build_id` in the table `PackageManifest`
                pub build_id: ::planus::alloc::string::String,
                /// The field `source_inventory_hash` in the table `PackageManifest`
                pub source_inventory_hash: ::planus::alloc::string::String,
                /// The field `payload_hash` in the table `PackageManifest`
                pub payload_hash: ::planus::alloc::string::String,
                /// The field `target_os` in the table `PackageManifest`
                pub target_os: ::planus::alloc::string::String,
                /// The field `target_arch` in the table `PackageManifest`
                pub target_arch: ::planus::alloc::string::String,
                /// The field `network_policy` in the table `PackageManifest`
                pub network_policy: ::planus::alloc::string::String,
                /// The field `files` in the table `PackageManifest`
                pub files: ::planus::alloc::vec::Vec<self::PackageFile>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for PackageManifest {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        package_format_version: ::core::default::Default::default(),
                        compiler_version: ::core::default::Default::default(),
                        runtime_abi_version: ::core::default::Default::default(),
                        domain_id: ::core::default::Default::default(),
                        domain_version: ::core::default::Default::default(),
                        build_id: ::core::default::Default::default(),
                        source_inventory_hash: ::core::default::Default::default(),
                        payload_hash: ::core::default::Default::default(),
                        target_os: ::core::default::Default::default(),
                        target_arch: ::core::default::Default::default(),
                        network_policy: ::core::default::Default::default(),
                        files: ::core::default::Default::default(),
                    }
                }
            }

            impl PackageManifest {
                /// Creates a [PackageManifestBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> PackageManifestBuilder<()> {
                    PackageManifestBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_package_format_version: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_compiler_version: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_runtime_abi_version: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_domain_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_domain_version: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_build_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_source_inventory_hash: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_payload_hash: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_target_os: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_target_arch: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_network_policy: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_files: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::PackageFile>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_package_format_version =
                        field_package_format_version.prepare(builder);
                    let prepared_compiler_version = field_compiler_version.prepare(builder);
                    let prepared_runtime_abi_version = field_runtime_abi_version.prepare(builder);
                    let prepared_domain_id = field_domain_id.prepare(builder);
                    let prepared_domain_version = field_domain_version.prepare(builder);
                    let prepared_build_id = field_build_id.prepare(builder);
                    let prepared_source_inventory_hash =
                        field_source_inventory_hash.prepare(builder);
                    let prepared_payload_hash = field_payload_hash.prepare(builder);
                    let prepared_target_os = field_target_os.prepare(builder);
                    let prepared_target_arch = field_target_arch.prepare(builder);
                    let prepared_network_policy = field_network_policy.prepare(builder);
                    let prepared_files = field_files.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<30> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    table_writer.write_entry::<::planus::Offset<str>>(4);
                    table_writer.write_entry::<::planus::Offset<str>>(5);
                    table_writer.write_entry::<::planus::Offset<str>>(6);
                    table_writer.write_entry::<::planus::Offset<str>>(7);
                    table_writer.write_entry::<::planus::Offset<str>>(8);
                    table_writer.write_entry::<::planus::Offset<str>>(9);
                    table_writer.write_entry::<::planus::Offset<str>>(10);
                    table_writer.write_entry::<::planus::Offset<str>>(11);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::PackageFile>]>>(12);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_package_format_version);
                            object_writer.write::<_, _, 4>(&prepared_compiler_version);
                            object_writer.write::<_, _, 4>(&prepared_runtime_abi_version);
                            object_writer.write::<_, _, 4>(&prepared_domain_id);
                            object_writer.write::<_, _, 4>(&prepared_domain_version);
                            object_writer.write::<_, _, 4>(&prepared_build_id);
                            object_writer.write::<_, _, 4>(&prepared_source_inventory_hash);
                            object_writer.write::<_, _, 4>(&prepared_payload_hash);
                            object_writer.write::<_, _, 4>(&prepared_target_os);
                            object_writer.write::<_, _, 4>(&prepared_target_arch);
                            object_writer.write::<_, _, 4>(&prepared_network_policy);
                            object_writer.write::<_, _, 4>(&prepared_files);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<PackageManifest>> for PackageManifest {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageManifest> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<PackageManifest>> for PackageManifest {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<PackageManifest>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<PackageManifest> for PackageManifest {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageManifest> {
                    PackageManifest::create(
                        builder,
                        self.schema_version,
                        &self.package_format_version,
                        &self.compiler_version,
                        &self.runtime_abi_version,
                        &self.domain_id,
                        &self.domain_version,
                        &self.build_id,
                        &self.source_inventory_hash,
                        &self.payload_hash,
                        &self.target_os,
                        &self.target_arch,
                        &self.network_policy,
                        &self.files,
                    )
                }
            }

            /// Builder for serializing an instance of the [PackageManifest] type.
            ///
            /// Can be created using the [PackageManifest::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct PackageManifestBuilder<State>(State);

            impl PackageManifestBuilder<()> {
                /// Setter for the [`schema_version` field](PackageManifest#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> PackageManifestBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    PackageManifestBuilder((value,))
                }

                /// Sets the [`schema_version` field](PackageManifest#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> PackageManifestBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> PackageManifestBuilder<(T0,)> {
                /// Setter for the [`package_format_version` field](PackageManifest#structfield.package_format_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn package_format_version<T1>(
                    self,
                    value: T1,
                ) -> PackageManifestBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    PackageManifestBuilder((v0, value))
                }
            }

            impl<T0, T1> PackageManifestBuilder<(T0, T1)> {
                /// Setter for the [`compiler_version` field](PackageManifest#structfield.compiler_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn compiler_version<T2>(self, value: T2) -> PackageManifestBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    PackageManifestBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> PackageManifestBuilder<(T0, T1, T2)> {
                /// Setter for the [`runtime_abi_version` field](PackageManifest#structfield.runtime_abi_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn runtime_abi_version<T3>(
                    self,
                    value: T3,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    PackageManifestBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> PackageManifestBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`domain_id` field](PackageManifest#structfield.domain_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn domain_id<T4>(
                    self,
                    value: T4,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> PackageManifestBuilder<(T0, T1, T2, T3, T4)> {
                /// Setter for the [`domain_version` field](PackageManifest#structfield.domain_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn domain_version<T5>(
                    self,
                    value: T5,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5)>
                where
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5)> {
                /// Setter for the [`build_id` field](PackageManifest#structfield.build_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn build_id<T6>(
                    self,
                    value: T6,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6)>
                where
                    T6: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, v5, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6)> {
                /// Setter for the [`source_inventory_hash` field](PackageManifest#structfield.source_inventory_hash).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn source_inventory_hash<T7>(
                    self,
                    value: T7,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)>
                where
                    T7: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, v5, v6, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)> {
                /// Setter for the [`payload_hash` field](PackageManifest#structfield.payload_hash).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn payload_hash<T8>(
                    self,
                    value: T8,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)>
                where
                    T8: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, v5, v6, v7, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8>
                PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)>
            {
                /// Setter for the [`target_os` field](PackageManifest#structfield.target_os).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn target_os<T9>(
                    self,
                    value: T9,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
                where
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9>
                PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
            {
                /// Setter for the [`target_arch` field](PackageManifest#structfield.target_arch).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn target_arch<T10>(
                    self,
                    value: T10,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
                where
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>
                PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
            {
                /// Setter for the [`network_policy` field](PackageManifest#structfield.network_policy).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn network_policy<T11>(
                    self,
                    value: T11,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
                where
                    T11: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) = self.0;
                    PackageManifestBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>
                PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
            {
                /// Setter for the [`files` field](PackageManifest#structfield.files).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn files<T12>(
                    self,
                    value: T12,
                ) -> PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
                where
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::PackageFile>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) = self.0;
                    PackageManifestBuilder((
                        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, value,
                    ))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>
                PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [PackageManifest].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageManifest>
                where
                    Self: ::planus::WriteAsOffset<PackageManifest>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                    T6: ::planus::WriteAs<::planus::Offset<str>>,
                    T7: ::planus::WriteAs<::planus::Offset<str>>,
                    T8: ::planus::WriteAs<::planus::Offset<str>>,
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                    T11: ::planus::WriteAs<::planus::Offset<str>>,
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::PackageFile>]>>,
                > ::planus::WriteAs<::planus::Offset<PackageManifest>>
                for PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                type Prepared = ::planus::Offset<PackageManifest>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageManifest> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                    T6: ::planus::WriteAs<::planus::Offset<str>>,
                    T7: ::planus::WriteAs<::planus::Offset<str>>,
                    T8: ::planus::WriteAs<::planus::Offset<str>>,
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                    T11: ::planus::WriteAs<::planus::Offset<str>>,
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::PackageFile>]>>,
                > ::planus::WriteAsOptional<::planus::Offset<PackageManifest>>
                for PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                type Prepared = ::planus::Offset<PackageManifest>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<PackageManifest>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<str>>,
                    T5: ::planus::WriteAs<::planus::Offset<str>>,
                    T6: ::planus::WriteAs<::planus::Offset<str>>,
                    T7: ::planus::WriteAs<::planus::Offset<str>>,
                    T8: ::planus::WriteAs<::planus::Offset<str>>,
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                    T11: ::planus::WriteAs<::planus::Offset<str>>,
                    T12: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::PackageFile>]>>,
                > ::planus::WriteAsOffset<PackageManifest>
                for PackageManifestBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PackageManifest> {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) = &self.0;
                    PackageManifest::create(
                        builder, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12,
                    )
                }
            }

            /// Reference to a deserialized [PackageManifest].
            #[derive(Copy, Clone)]
            pub struct PackageManifestRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> PackageManifestRef<'a> {
                /// Getter for the [`schema_version` field](PackageManifest#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "PackageManifest", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`package_format_version` field](PackageManifest#structfield.package_format_version).
                #[inline]
                pub fn package_format_version(
                    &self,
                ) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(1, "PackageManifest", "package_format_version")
                }

                /// Getter for the [`compiler_version` field](PackageManifest#structfield.compiler_version).
                #[inline]
                pub fn compiler_version(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(2, "PackageManifest", "compiler_version")
                }

                /// Getter for the [`runtime_abi_version` field](PackageManifest#structfield.runtime_abi_version).
                #[inline]
                pub fn runtime_abi_version(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(3, "PackageManifest", "runtime_abi_version")
                }

                /// Getter for the [`domain_id` field](PackageManifest#structfield.domain_id).
                #[inline]
                pub fn domain_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(4, "PackageManifest", "domain_id")
                }

                /// Getter for the [`domain_version` field](PackageManifest#structfield.domain_version).
                #[inline]
                pub fn domain_version(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(5, "PackageManifest", "domain_version")
                }

                /// Getter for the [`build_id` field](PackageManifest#structfield.build_id).
                #[inline]
                pub fn build_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(6, "PackageManifest", "build_id")
                }

                /// Getter for the [`source_inventory_hash` field](PackageManifest#structfield.source_inventory_hash).
                #[inline]
                pub fn source_inventory_hash(
                    &self,
                ) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(7, "PackageManifest", "source_inventory_hash")
                }

                /// Getter for the [`payload_hash` field](PackageManifest#structfield.payload_hash).
                #[inline]
                pub fn payload_hash(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(8, "PackageManifest", "payload_hash")
                }

                /// Getter for the [`target_os` field](PackageManifest#structfield.target_os).
                #[inline]
                pub fn target_os(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(9, "PackageManifest", "target_os")
                }

                /// Getter for the [`target_arch` field](PackageManifest#structfield.target_arch).
                #[inline]
                pub fn target_arch(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(10, "PackageManifest", "target_arch")
                }

                /// Getter for the [`network_policy` field](PackageManifest#structfield.network_policy).
                #[inline]
                pub fn network_policy(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(11, "PackageManifest", "network_policy")
                }

                /// Getter for the [`files` field](PackageManifest#structfield.files).
                #[inline]
                pub fn files(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::PackageFileRef<'a>>>,
                > {
                    self.0.access_required(12, "PackageManifest", "files")
                }
            }

            impl<'a> ::core::fmt::Debug for PackageManifestRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("PackageManifestRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("package_format_version", &self.package_format_version());
                    f.field("compiler_version", &self.compiler_version());
                    f.field("runtime_abi_version", &self.runtime_abi_version());
                    f.field("domain_id", &self.domain_id());
                    f.field("domain_version", &self.domain_version());
                    f.field("build_id", &self.build_id());
                    f.field("source_inventory_hash", &self.source_inventory_hash());
                    f.field("payload_hash", &self.payload_hash());
                    f.field("target_os", &self.target_os());
                    f.field("target_arch", &self.target_arch());
                    f.field("network_policy", &self.network_policy());
                    f.field("files", &self.files());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<PackageManifestRef<'a>> for PackageManifest {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: PackageManifestRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        package_format_version: ::core::convert::Into::into(
                            value.package_format_version()?,
                        ),
                        compiler_version: ::core::convert::Into::into(value.compiler_version()?),
                        runtime_abi_version: ::core::convert::Into::into(
                            value.runtime_abi_version()?,
                        ),
                        domain_id: ::core::convert::Into::into(value.domain_id()?),
                        domain_version: ::core::convert::Into::into(value.domain_version()?),
                        build_id: ::core::convert::Into::into(value.build_id()?),
                        source_inventory_hash: ::core::convert::Into::into(
                            value.source_inventory_hash()?,
                        ),
                        payload_hash: ::core::convert::Into::into(value.payload_hash()?),
                        target_os: ::core::convert::Into::into(value.target_os()?),
                        target_arch: ::core::convert::Into::into(value.target_arch()?),
                        network_policy: ::core::convert::Into::into(value.network_policy()?),
                        files: value.files()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for PackageManifestRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for PackageManifestRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[PackageManifestRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<PackageManifest>> for PackageManifest {
                type Value = ::planus::Offset<PackageManifest>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<PackageManifest>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for PackageManifestRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[PackageManifestRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `AccessLabel` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `AccessLabel` in the file `schemas\flatbuffers\policies.fbs:5`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct AccessLabel {
                /// The field `resource` in the table `AccessLabel`
                pub resource: ::planus::alloc::string::String,
                /// The field `label` in the table `AccessLabel`
                pub label: ::planus::alloc::string::String,
                /// The field `provenance_id` in the table `AccessLabel`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for AccessLabel {
                fn default() -> Self {
                    Self {
                        resource: ::core::default::Default::default(),
                        label: ::core::default::Default::default(),
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl AccessLabel {
                /// Creates a [AccessLabelBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> AccessLabelBuilder<()> {
                    AccessLabelBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_resource: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_label: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_resource = field_resource.prepare(builder);
                    let prepared_label = field_label.prepare(builder);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<10> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(2);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_resource);
                            object_writer.write::<_, _, 4>(&prepared_label);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<AccessLabel>> for AccessLabel {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<AccessLabel> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<AccessLabel>> for AccessLabel {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<AccessLabel>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<AccessLabel> for AccessLabel {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<AccessLabel> {
                    AccessLabel::create(builder, &self.resource, &self.label, &self.provenance_id)
                }
            }

            /// Builder for serializing an instance of the [AccessLabel] type.
            ///
            /// Can be created using the [AccessLabel::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct AccessLabelBuilder<State>(State);

            impl AccessLabelBuilder<()> {
                /// Setter for the [`resource` field](AccessLabel#structfield.resource).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn resource<T0>(self, value: T0) -> AccessLabelBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    AccessLabelBuilder((value,))
                }
            }

            impl<T0> AccessLabelBuilder<(T0,)> {
                /// Setter for the [`label` field](AccessLabel#structfield.label).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn label<T1>(self, value: T1) -> AccessLabelBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    AccessLabelBuilder((v0, value))
                }
            }

            impl<T0, T1> AccessLabelBuilder<(T0, T1)> {
                /// Setter for the [`provenance_id` field](AccessLabel#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T2>(self, value: T2) -> AccessLabelBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    AccessLabelBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> AccessLabelBuilder<(T0, T1, T2)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [AccessLabel].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<AccessLabel>
                where
                    Self: ::planus::WriteAsOffset<AccessLabel>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<AccessLabel>>
                for AccessLabelBuilder<(T0, T1, T2)>
            {
                type Prepared = ::planus::Offset<AccessLabel>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<AccessLabel> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<AccessLabel>>
                for AccessLabelBuilder<(T0, T1, T2)>
            {
                type Prepared = ::planus::Offset<AccessLabel>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<AccessLabel>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<AccessLabel> for AccessLabelBuilder<(T0, T1, T2)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<AccessLabel> {
                    let (v0, v1, v2) = &self.0;
                    AccessLabel::create(builder, v0, v1, v2)
                }
            }

            /// Reference to a deserialized [AccessLabel].
            #[derive(Copy, Clone)]
            pub struct AccessLabelRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> AccessLabelRef<'a> {
                /// Getter for the [`resource` field](AccessLabel#structfield.resource).
                #[inline]
                pub fn resource(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "AccessLabel", "resource")
                }

                /// Getter for the [`label` field](AccessLabel#structfield.label).
                #[inline]
                pub fn label(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "AccessLabel", "label")
                }

                /// Getter for the [`provenance_id` field](AccessLabel#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "AccessLabel", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for AccessLabelRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("AccessLabelRef");
                    f.field("resource", &self.resource());
                    f.field("label", &self.label());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<AccessLabelRef<'a>> for AccessLabel {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: AccessLabelRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        resource: ::core::convert::Into::into(value.resource()?),
                        label: ::core::convert::Into::into(value.label()?),
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for AccessLabelRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for AccessLabelRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[AccessLabelRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<AccessLabel>> for AccessLabel {
                type Value = ::planus::Offset<AccessLabel>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<AccessLabel>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for AccessLabelRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[AccessLabelRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `ConfidenceThreshold` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `ConfidenceThreshold` in the file `schemas\flatbuffers\policies.fbs:11`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct ConfidenceThreshold {
                /// The field `skill_id` in the table `ConfidenceThreshold`
                pub skill_id: ::planus::alloc::string::String,
                /// The field `minimum` in the table `ConfidenceThreshold`
                pub minimum: f64,
                /// The field `fallback` in the table `ConfidenceThreshold`
                pub fallback: ::planus::alloc::string::String,
                /// The field `provenance_id` in the table `ConfidenceThreshold`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for ConfidenceThreshold {
                fn default() -> Self {
                    Self {
                        skill_id: ::core::default::Default::default(),
                        minimum: 0.0,
                        fallback: ::core::default::Default::default(),
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl ConfidenceThreshold {
                /// Creates a [ConfidenceThresholdBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ConfidenceThresholdBuilder<()> {
                    ConfidenceThresholdBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_skill_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_minimum: impl ::planus::WriteAsDefault<f64, f64>,
                    field_fallback: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_skill_id = field_skill_id.prepare(builder);
                    let prepared_minimum = field_minimum.prepare(builder, &0.0);
                    let prepared_fallback = field_fallback.prepare(builder);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<12> =
                        ::core::default::Default::default();
                    if prepared_minimum.is_some() {
                        table_writer.write_entry::<f64>(1);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer.write_entry::<::planus::Offset<str>>(3);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_minimum) = prepared_minimum
                            {
                                object_writer.write::<_, _, 8>(&prepared_minimum);
                            }
                            object_writer.write::<_, _, 4>(&prepared_skill_id);
                            object_writer.write::<_, _, 4>(&prepared_fallback);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<ConfidenceThreshold>> for ConfidenceThreshold {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ConfidenceThreshold> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<ConfidenceThreshold>> for ConfidenceThreshold {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ConfidenceThreshold>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<ConfidenceThreshold> for ConfidenceThreshold {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ConfidenceThreshold> {
                    ConfidenceThreshold::create(
                        builder,
                        &self.skill_id,
                        self.minimum,
                        &self.fallback,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [ConfidenceThreshold] type.
            ///
            /// Can be created using the [ConfidenceThreshold::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ConfidenceThresholdBuilder<State>(State);

            impl ConfidenceThresholdBuilder<()> {
                /// Setter for the [`skill_id` field](ConfidenceThreshold#structfield.skill_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn skill_id<T0>(self, value: T0) -> ConfidenceThresholdBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    ConfidenceThresholdBuilder((value,))
                }
            }

            impl<T0> ConfidenceThresholdBuilder<(T0,)> {
                /// Setter for the [`minimum` field](ConfidenceThreshold#structfield.minimum).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn minimum<T1>(self, value: T1) -> ConfidenceThresholdBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAsDefault<f64, f64>,
                {
                    let (v0,) = self.0;
                    ConfidenceThresholdBuilder((v0, value))
                }

                /// Sets the [`minimum` field](ConfidenceThreshold#structfield.minimum) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn minimum_as_default(
                    self,
                ) -> ConfidenceThresholdBuilder<(T0, ::planus::DefaultValue)> {
                    self.minimum(::planus::DefaultValue)
                }
            }

            impl<T0, T1> ConfidenceThresholdBuilder<(T0, T1)> {
                /// Setter for the [`fallback` field](ConfidenceThreshold#structfield.fallback).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn fallback<T2>(self, value: T2) -> ConfidenceThresholdBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    ConfidenceThresholdBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> ConfidenceThresholdBuilder<(T0, T1, T2)> {
                /// Setter for the [`provenance_id` field](ConfidenceThreshold#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T3>(
                    self,
                    value: T3,
                ) -> ConfidenceThresholdBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    ConfidenceThresholdBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> ConfidenceThresholdBuilder<(T0, T1, T2, T3)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [ConfidenceThreshold].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ConfidenceThreshold>
                where
                    Self: ::planus::WriteAsOffset<ConfidenceThreshold>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<f64, f64>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<ConfidenceThreshold>>
                for ConfidenceThresholdBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<ConfidenceThreshold>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ConfidenceThreshold> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<f64, f64>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<ConfidenceThreshold>>
                for ConfidenceThresholdBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<ConfidenceThreshold>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ConfidenceThreshold>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<f64, f64>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<ConfidenceThreshold>
                for ConfidenceThresholdBuilder<(T0, T1, T2, T3)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ConfidenceThreshold> {
                    let (v0, v1, v2, v3) = &self.0;
                    ConfidenceThreshold::create(builder, v0, v1, v2, v3)
                }
            }

            /// Reference to a deserialized [ConfidenceThreshold].
            #[derive(Copy, Clone)]
            pub struct ConfidenceThresholdRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ConfidenceThresholdRef<'a> {
                /// Getter for the [`skill_id` field](ConfidenceThreshold#structfield.skill_id).
                #[inline]
                pub fn skill_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "ConfidenceThreshold", "skill_id")
                }

                /// Getter for the [`minimum` field](ConfidenceThreshold#structfield.minimum).
                #[inline]
                pub fn minimum(&self) -> ::planus::Result<f64> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(1, "ConfidenceThreshold", "minimum")?
                            .unwrap_or(0.0),
                    )
                }

                /// Getter for the [`fallback` field](ConfidenceThreshold#structfield.fallback).
                #[inline]
                pub fn fallback(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "ConfidenceThreshold", "fallback")
                }

                /// Getter for the [`provenance_id` field](ConfidenceThreshold#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(3, "ConfidenceThreshold", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for ConfidenceThresholdRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ConfidenceThresholdRef");
                    f.field("skill_id", &self.skill_id());
                    f.field("minimum", &self.minimum());
                    f.field("fallback", &self.fallback());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ConfidenceThresholdRef<'a>> for ConfidenceThreshold {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ConfidenceThresholdRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        skill_id: ::core::convert::Into::into(value.skill_id()?),
                        minimum: ::core::convert::TryInto::try_into(value.minimum()?)?,
                        fallback: ::core::convert::Into::into(value.fallback()?),
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ConfidenceThresholdRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ConfidenceThresholdRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ConfidenceThresholdRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<ConfidenceThreshold>> for ConfidenceThreshold {
                type Value = ::planus::Offset<ConfidenceThreshold>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<ConfidenceThreshold>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ConfidenceThresholdRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ConfidenceThresholdRef]",
                            "read_as_root",
                            0,
                        )
                    })
                }
            }

            /// The table `ActionPermission` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `ActionPermission` in the file `schemas\flatbuffers\policies.fbs:18`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct ActionPermission {
                /// The field `action` in the table `ActionPermission`
                pub action: ::planus::alloc::string::String,
                /// The field `allowed` in the table `ActionPermission`
                pub allowed: bool,
                /// The field `requires_human_review` in the table `ActionPermission`
                pub requires_human_review: bool,
                /// The field `provenance_id` in the table `ActionPermission`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for ActionPermission {
                fn default() -> Self {
                    Self {
                        action: ::core::default::Default::default(),
                        allowed: false,
                        requires_human_review: false,
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl ActionPermission {
                /// Creates a [ActionPermissionBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> ActionPermissionBuilder<()> {
                    ActionPermissionBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_action: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_allowed: impl ::planus::WriteAsDefault<bool, bool>,
                    field_requires_human_review: impl ::planus::WriteAsDefault<bool, bool>,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_action = field_action.prepare(builder);
                    let prepared_allowed = field_allowed.prepare(builder, &false);
                    let prepared_requires_human_review =
                        field_requires_human_review.prepare(builder, &false);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<12> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    if prepared_allowed.is_some() {
                        table_writer.write_entry::<bool>(1);
                    }
                    if prepared_requires_human_review.is_some() {
                        table_writer.write_entry::<bool>(2);
                    }

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_action);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                            if let ::core::option::Option::Some(prepared_allowed) = prepared_allowed
                            {
                                object_writer.write::<_, _, 1>(&prepared_allowed);
                            }
                            if let ::core::option::Option::Some(prepared_requires_human_review) =
                                prepared_requires_human_review
                            {
                                object_writer.write::<_, _, 1>(&prepared_requires_human_review);
                            }
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<ActionPermission>> for ActionPermission {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ActionPermission> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<ActionPermission>> for ActionPermission {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ActionPermission>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<ActionPermission> for ActionPermission {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ActionPermission> {
                    ActionPermission::create(
                        builder,
                        &self.action,
                        self.allowed,
                        self.requires_human_review,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [ActionPermission] type.
            ///
            /// Can be created using the [ActionPermission::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct ActionPermissionBuilder<State>(State);

            impl ActionPermissionBuilder<()> {
                /// Setter for the [`action` field](ActionPermission#structfield.action).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn action<T0>(self, value: T0) -> ActionPermissionBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    ActionPermissionBuilder((value,))
                }
            }

            impl<T0> ActionPermissionBuilder<(T0,)> {
                /// Setter for the [`allowed` field](ActionPermission#structfield.allowed).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn allowed<T1>(self, value: T1) -> ActionPermissionBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0,) = self.0;
                    ActionPermissionBuilder((v0, value))
                }

                /// Sets the [`allowed` field](ActionPermission#structfield.allowed) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn allowed_as_default(
                    self,
                ) -> ActionPermissionBuilder<(T0, ::planus::DefaultValue)> {
                    self.allowed(::planus::DefaultValue)
                }
            }

            impl<T0, T1> ActionPermissionBuilder<(T0, T1)> {
                /// Setter for the [`requires_human_review` field](ActionPermission#structfield.requires_human_review).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn requires_human_review<T2>(
                    self,
                    value: T2,
                ) -> ActionPermissionBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1) = self.0;
                    ActionPermissionBuilder((v0, v1, value))
                }

                /// Sets the [`requires_human_review` field](ActionPermission#structfield.requires_human_review) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn requires_human_review_as_default(
                    self,
                ) -> ActionPermissionBuilder<(T0, T1, ::planus::DefaultValue)> {
                    self.requires_human_review(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2> ActionPermissionBuilder<(T0, T1, T2)> {
                /// Setter for the [`provenance_id` field](ActionPermission#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T3>(
                    self,
                    value: T3,
                ) -> ActionPermissionBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    ActionPermissionBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> ActionPermissionBuilder<(T0, T1, T2, T3)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [ActionPermission].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ActionPermission>
                where
                    Self: ::planus::WriteAsOffset<ActionPermission>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<bool, bool>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<ActionPermission>>
                for ActionPermissionBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<ActionPermission>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ActionPermission> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<bool, bool>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<ActionPermission>>
                for ActionPermissionBuilder<(T0, T1, T2, T3)>
            {
                type Prepared = ::planus::Offset<ActionPermission>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<ActionPermission>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAsDefault<bool, bool>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<ActionPermission>
                for ActionPermissionBuilder<(T0, T1, T2, T3)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<ActionPermission> {
                    let (v0, v1, v2, v3) = &self.0;
                    ActionPermission::create(builder, v0, v1, v2, v3)
                }
            }

            /// Reference to a deserialized [ActionPermission].
            #[derive(Copy, Clone)]
            pub struct ActionPermissionRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> ActionPermissionRef<'a> {
                /// Getter for the [`action` field](ActionPermission#structfield.action).
                #[inline]
                pub fn action(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "ActionPermission", "action")
                }

                /// Getter for the [`allowed` field](ActionPermission#structfield.allowed).
                #[inline]
                pub fn allowed(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(1, "ActionPermission", "allowed")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`requires_human_review` field](ActionPermission#structfield.requires_human_review).
                #[inline]
                pub fn requires_human_review(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(2, "ActionPermission", "requires_human_review")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`provenance_id` field](ActionPermission#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0
                        .access_required(3, "ActionPermission", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for ActionPermissionRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("ActionPermissionRef");
                    f.field("action", &self.action());
                    f.field("allowed", &self.allowed());
                    f.field("requires_human_review", &self.requires_human_review());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<ActionPermissionRef<'a>> for ActionPermission {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: ActionPermissionRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        action: ::core::convert::Into::into(value.action()?),
                        allowed: ::core::convert::TryInto::try_into(value.allowed()?)?,
                        requires_human_review: ::core::convert::TryInto::try_into(
                            value.requires_human_review()?,
                        )?,
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for ActionPermissionRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for ActionPermissionRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[ActionPermissionRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<ActionPermission>> for ActionPermission {
                type Value = ::planus::Offset<ActionPermission>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<ActionPermission>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for ActionPermissionRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[ActionPermissionRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `PolicyBundle` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `PolicyBundle` in the file `schemas\flatbuffers\policies.fbs:25`
            #[derive(
                Clone, Debug, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
            )]
            pub struct PolicyBundle {
                /// The field `schema_version` in the table `PolicyBundle`
                pub schema_version: u32,
                /// The field `default_action` in the table `PolicyBundle`
                pub default_action: ::planus::alloc::string::String,
                /// The field `network_allowed` in the table `PolicyBundle`
                pub network_allowed: bool,
                /// The field `access_labels` in the table `PolicyBundle`
                pub access_labels: ::planus::alloc::vec::Vec<self::AccessLabel>,
                /// The field `confidence_thresholds` in the table `PolicyBundle`
                pub confidence_thresholds: ::planus::alloc::vec::Vec<self::ConfidenceThreshold>,
                /// The field `action_permissions` in the table `PolicyBundle`
                pub action_permissions: ::planus::alloc::vec::Vec<self::ActionPermission>,
                /// The field `allowed_executors` in the table `PolicyBundle`
                pub allowed_executors: ::planus::alloc::vec::Vec<::planus::alloc::string::String>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for PolicyBundle {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        default_action: ::core::default::Default::default(),
                        network_allowed: false,
                        access_labels: ::core::default::Default::default(),
                        confidence_thresholds: ::core::default::Default::default(),
                        action_permissions: ::core::default::Default::default(),
                        allowed_executors: ::core::default::Default::default(),
                    }
                }
            }

            impl PolicyBundle {
                /// Creates a [PolicyBundleBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> PolicyBundleBuilder<()> {
                    PolicyBundleBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_default_action: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_network_allowed: impl ::planus::WriteAsDefault<bool, bool>,
                    field_access_labels: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::AccessLabel>]>,
                    >,
                    field_confidence_thresholds: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ConfidenceThreshold>]>,
                    >,
                    field_action_permissions: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ActionPermission>]>,
                    >,
                    field_allowed_executors: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<str>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_default_action = field_default_action.prepare(builder);
                    let prepared_network_allowed = field_network_allowed.prepare(builder, &false);
                    let prepared_access_labels = field_access_labels.prepare(builder);
                    let prepared_confidence_thresholds =
                        field_confidence_thresholds.prepare(builder);
                    let prepared_action_permissions = field_action_permissions.prepare(builder);
                    let prepared_allowed_executors = field_allowed_executors.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<18> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::AccessLabel>]>>(3);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<self::ConfidenceThreshold>]>>(4);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<self::ActionPermission>]>>(5);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<str>]>>(6);
                    if prepared_network_allowed.is_some() {
                        table_writer.write_entry::<bool>(2);
                    }

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_default_action);
                            object_writer.write::<_, _, 4>(&prepared_access_labels);
                            object_writer.write::<_, _, 4>(&prepared_confidence_thresholds);
                            object_writer.write::<_, _, 4>(&prepared_action_permissions);
                            object_writer.write::<_, _, 4>(&prepared_allowed_executors);
                            if let ::core::option::Option::Some(prepared_network_allowed) =
                                prepared_network_allowed
                            {
                                object_writer.write::<_, _, 1>(&prepared_network_allowed);
                            }
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<PolicyBundle>> for PolicyBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PolicyBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<PolicyBundle>> for PolicyBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<PolicyBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<PolicyBundle> for PolicyBundle {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PolicyBundle> {
                    PolicyBundle::create(
                        builder,
                        self.schema_version,
                        &self.default_action,
                        self.network_allowed,
                        &self.access_labels,
                        &self.confidence_thresholds,
                        &self.action_permissions,
                        &self.allowed_executors,
                    )
                }
            }

            /// Builder for serializing an instance of the [PolicyBundle] type.
            ///
            /// Can be created using the [PolicyBundle::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct PolicyBundleBuilder<State>(State);

            impl PolicyBundleBuilder<()> {
                /// Setter for the [`schema_version` field](PolicyBundle#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> PolicyBundleBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    PolicyBundleBuilder((value,))
                }

                /// Sets the [`schema_version` field](PolicyBundle#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> PolicyBundleBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> PolicyBundleBuilder<(T0,)> {
                /// Setter for the [`default_action` field](PolicyBundle#structfield.default_action).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn default_action<T1>(self, value: T1) -> PolicyBundleBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    PolicyBundleBuilder((v0, value))
                }
            }

            impl<T0, T1> PolicyBundleBuilder<(T0, T1)> {
                /// Setter for the [`network_allowed` field](PolicyBundle#structfield.network_allowed).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn network_allowed<T2>(self, value: T2) -> PolicyBundleBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1) = self.0;
                    PolicyBundleBuilder((v0, v1, value))
                }

                /// Sets the [`network_allowed` field](PolicyBundle#structfield.network_allowed) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn network_allowed_as_default(
                    self,
                ) -> PolicyBundleBuilder<(T0, T1, ::planus::DefaultValue)> {
                    self.network_allowed(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2> PolicyBundleBuilder<(T0, T1, T2)> {
                /// Setter for the [`access_labels` field](PolicyBundle#structfield.access_labels).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn access_labels<T3>(self, value: T3) -> PolicyBundleBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::AccessLabel>]>>,
                {
                    let (v0, v1, v2) = self.0;
                    PolicyBundleBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> PolicyBundleBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`confidence_thresholds` field](PolicyBundle#structfield.confidence_thresholds).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn confidence_thresholds<T4>(
                    self,
                    value: T4,
                ) -> PolicyBundleBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ConfidenceThreshold>]>,
                    >,
                {
                    let (v0, v1, v2, v3) = self.0;
                    PolicyBundleBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> PolicyBundleBuilder<(T0, T1, T2, T3, T4)> {
                /// Setter for the [`action_permissions` field](PolicyBundle#structfield.action_permissions).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn action_permissions<T5>(
                    self,
                    value: T5,
                ) -> PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5)>
                where
                    T5: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ActionPermission>]>,
                    >,
                {
                    let (v0, v1, v2, v3, v4) = self.0;
                    PolicyBundleBuilder((v0, v1, v2, v3, v4, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5> PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5)> {
                /// Setter for the [`allowed_executors` field](PolicyBundle#structfield.allowed_executors).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn allowed_executors<T6>(
                    self,
                    value: T6,
                ) -> PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)>
                where
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5) = self.0;
                    PolicyBundleBuilder((v0, v1, v2, v3, v4, v5, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6> PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [PolicyBundle].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PolicyBundle>
                where
                    Self: ::planus::WriteAsOffset<PolicyBundle>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::AccessLabel>]>>,
                    T4: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ConfidenceThreshold>]>,
                    >,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ActionPermission>]>>,
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                > ::planus::WriteAs<::planus::Offset<PolicyBundle>>
                for PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)>
            {
                type Prepared = ::planus::Offset<PolicyBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PolicyBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::AccessLabel>]>>,
                    T4: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ConfidenceThreshold>]>,
                    >,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ActionPermission>]>>,
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                > ::planus::WriteAsOptional<::planus::Offset<PolicyBundle>>
                for PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)>
            {
                type Prepared = ::planus::Offset<PolicyBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<PolicyBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAsDefault<bool, bool>,
                    T3: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::AccessLabel>]>>,
                    T4: ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::ConfidenceThreshold>]>,
                    >,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::ActionPermission>]>>,
                    T6: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                > ::planus::WriteAsOffset<PolicyBundle>
                for PolicyBundleBuilder<(T0, T1, T2, T3, T4, T5, T6)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<PolicyBundle> {
                    let (v0, v1, v2, v3, v4, v5, v6) = &self.0;
                    PolicyBundle::create(builder, v0, v1, v2, v3, v4, v5, v6)
                }
            }

            /// Reference to a deserialized [PolicyBundle].
            #[derive(Copy, Clone)]
            pub struct PolicyBundleRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> PolicyBundleRef<'a> {
                /// Getter for the [`schema_version` field](PolicyBundle#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "PolicyBundle", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`default_action` field](PolicyBundle#structfield.default_action).
                #[inline]
                pub fn default_action(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "PolicyBundle", "default_action")
                }

                /// Getter for the [`network_allowed` field](PolicyBundle#structfield.network_allowed).
                #[inline]
                pub fn network_allowed(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(2, "PolicyBundle", "network_allowed")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`access_labels` field](PolicyBundle#structfield.access_labels).
                #[inline]
                pub fn access_labels(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::AccessLabelRef<'a>>>,
                > {
                    self.0.access_required(3, "PolicyBundle", "access_labels")
                }

                /// Getter for the [`confidence_thresholds` field](PolicyBundle#structfield.confidence_thresholds).
                #[inline]
                pub fn confidence_thresholds(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::ConfidenceThresholdRef<'a>>>,
                > {
                    self.0
                        .access_required(4, "PolicyBundle", "confidence_thresholds")
                }

                /// Getter for the [`action_permissions` field](PolicyBundle#structfield.action_permissions).
                #[inline]
                pub fn action_permissions(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<self::ActionPermissionRef<'a>>>,
                > {
                    self.0
                        .access_required(5, "PolicyBundle", "action_permissions")
                }

                /// Getter for the [`allowed_executors` field](PolicyBundle#structfield.allowed_executors).
                #[inline]
                pub fn allowed_executors(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<&'a ::core::primitive::str>>,
                > {
                    self.0
                        .access_required(6, "PolicyBundle", "allowed_executors")
                }
            }

            impl<'a> ::core::fmt::Debug for PolicyBundleRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("PolicyBundleRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("default_action", &self.default_action());
                    f.field("network_allowed", &self.network_allowed());
                    f.field("access_labels", &self.access_labels());
                    f.field("confidence_thresholds", &self.confidence_thresholds());
                    f.field("action_permissions", &self.action_permissions());
                    f.field("allowed_executors", &self.allowed_executors());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<PolicyBundleRef<'a>> for PolicyBundle {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: PolicyBundleRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        default_action: ::core::convert::Into::into(value.default_action()?),
                        network_allowed: ::core::convert::TryInto::try_into(
                            value.network_allowed()?,
                        )?,
                        access_labels: value.access_labels()?.to_vec_result()?,
                        confidence_thresholds: value.confidence_thresholds()?.to_vec_result()?,
                        action_permissions: value.action_permissions()?.to_vec_result()?,
                        allowed_executors: value.allowed_executors()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for PolicyBundleRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for PolicyBundleRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[PolicyBundleRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<PolicyBundle>> for PolicyBundle {
                type Value = ::planus::Offset<PolicyBundle>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<PolicyBundle>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for PolicyBundleRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[PolicyBundleRef]", "read_as_root", 0)
                    })
                }
            }

            /// The enum `Criticality` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Enum `Criticality` in the file `schemas\flatbuffers\skills.fbs:5`
            #[derive(
                Copy,
                Clone,
                Debug,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            #[repr(u8)]
            pub enum Criticality {
                /// The variant `Low` in the enum `Criticality`
                Low = 0,

                /// The variant `Medium` in the enum `Criticality`
                Medium = 1,

                /// The variant `High` in the enum `Criticality`
                High = 2,

                /// The variant `Critical` in the enum `Criticality`
                Critical = 3,
            }

            impl Criticality {
                /// Array containing all valid variants of Criticality
                pub const ENUM_VALUES: [Self; 4] =
                    [Self::Low, Self::Medium, Self::High, Self::Critical];
            }

            impl ::core::convert::TryFrom<u8> for Criticality {
                type Error = ::planus::errors::UnknownEnumTagKind;
                #[inline]
                fn try_from(
                    value: u8,
                ) -> ::core::result::Result<Self, ::planus::errors::UnknownEnumTagKind>
                {
                    #[allow(clippy::match_single_binding)]
                    match value {
                        0 => ::core::result::Result::Ok(Criticality::Low),
                        1 => ::core::result::Result::Ok(Criticality::Medium),
                        2 => ::core::result::Result::Ok(Criticality::High),
                        3 => ::core::result::Result::Ok(Criticality::Critical),

                        _ => ::core::result::Result::Err(::planus::errors::UnknownEnumTagKind {
                            tag: value as i128,
                        }),
                    }
                }
            }

            impl ::core::convert::From<Criticality> for u8 {
                #[inline]
                fn from(value: Criticality) -> Self {
                    value as u8
                }
            }

            /// # Safety
            /// The Planus compiler correctly calculates `ALIGNMENT` and `SIZE`.
            unsafe impl ::planus::Primitive for Criticality {
                const ALIGNMENT: usize = 1;
                const SIZE: usize = 1;
            }

            impl ::planus::WriteAsPrimitive<Criticality> for Criticality {
                #[inline]
                fn write<const N: usize>(
                    &self,
                    cursor: ::planus::Cursor<'_, N>,
                    buffer_position: u32,
                ) {
                    (*self as u8).write(cursor, buffer_position);
                }
            }

            impl ::planus::WriteAs<Criticality> for Criticality {
                type Prepared = Self;

                #[inline]
                fn prepare(&self, _builder: &mut ::planus::Builder) -> Criticality {
                    *self
                }
            }

            impl ::planus::WriteAsDefault<Criticality, Criticality> for Criticality {
                type Prepared = Self;

                #[inline]
                fn prepare(
                    &self,
                    _builder: &mut ::planus::Builder,
                    default: &Criticality,
                ) -> ::core::option::Option<Criticality> {
                    if self == default {
                        ::core::option::Option::None
                    } else {
                        ::core::option::Option::Some(*self)
                    }
                }
            }

            impl ::planus::WriteAsOptional<Criticality> for Criticality {
                type Prepared = Self;

                #[inline]
                fn prepare(
                    &self,
                    _builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<Criticality> {
                    ::core::option::Option::Some(*self)
                }
            }

            impl<'buf> ::planus::TableRead<'buf> for Criticality {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'buf>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    let n: u8 = ::planus::TableRead::from_buffer(buffer, offset)?;
                    ::core::result::Result::Ok(::core::convert::TryInto::try_into(n)?)
                }
            }

            impl<'buf> ::planus::VectorReadInner<'buf> for Criticality {
                type Error = ::planus::errors::UnknownEnumTag;
                const STRIDE: usize = 1;
                #[inline]
                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'buf>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::UnknownEnumTag>
                {
                    let value = unsafe { *buffer.buffer.get_unchecked(offset) };
                    let value: ::core::result::Result<Self, _> =
                        ::core::convert::TryInto::try_into(value);
                    value.map_err(|error_kind| {
                        error_kind.with_error_location(
                            "Criticality",
                            "VectorRead::from_buffer",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<Criticality> for Criticality {
                const STRIDE: usize = 1;

                type Value = Self;

                #[inline]
                fn prepare(&self, _builder: &mut ::planus::Builder) -> Self {
                    *self
                }

                #[inline]
                unsafe fn write_values(
                    values: &[Self],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 1];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - i as u32,
                        );
                    }
                }
            }

            /// The table `Skill` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `Skill` in the file `schemas\flatbuffers\skills.fbs:12`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct Skill {
                /// The field `id` in the table `Skill`
                pub id: ::planus::alloc::string::String,
                /// The field `version` in the table `Skill`
                pub version: ::planus::alloc::string::String,
                /// The field `input_schema` in the table `Skill`
                pub input_schema: ::planus::alloc::string::String,
                /// The field `output_schema` in the table `Skill`
                pub output_schema: ::planus::alloc::string::String,
                /// The field `preconditions` in the table `Skill`
                pub preconditions: ::planus::alloc::vec::Vec<::planus::alloc::string::String>,
                /// The field `postconditions` in the table `Skill`
                pub postconditions: ::planus::alloc::vec::Vec<::planus::alloc::string::String>,
                /// The field `criticality` in the table `Skill`
                pub criticality: self::Criticality,
                /// The field `fallback` in the table `Skill`
                pub fallback: ::core::option::Option<::planus::alloc::string::String>,
                /// The field `evidence_required` in the table `Skill`
                pub evidence_required: bool,
                /// The field `evaluation_dataset` in the table `Skill`
                pub evaluation_dataset: ::planus::alloc::string::String,
                /// The field `evaluation_thresholds` in the table `Skill`
                pub evaluation_thresholds: ::planus::alloc::string::String,
                /// The field `candidate_executors` in the table `Skill`
                pub candidate_executors: ::planus::alloc::vec::Vec<::planus::alloc::string::String>,
                /// The field `provenance_id` in the table `Skill`
                pub provenance_id: ::planus::alloc::string::String,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for Skill {
                fn default() -> Self {
                    Self {
                        id: ::core::default::Default::default(),
                        version: ::core::default::Default::default(),
                        input_schema: ::core::default::Default::default(),
                        output_schema: ::core::default::Default::default(),
                        preconditions: ::core::default::Default::default(),
                        postconditions: ::core::default::Default::default(),
                        criticality: self::Criticality::Low,
                        fallback: ::core::default::Default::default(),
                        evidence_required: false,
                        evaluation_dataset: ::core::default::Default::default(),
                        evaluation_thresholds: ::core::default::Default::default(),
                        candidate_executors: ::core::default::Default::default(),
                        provenance_id: ::core::default::Default::default(),
                    }
                }
            }

            impl Skill {
                /// Creates a [SkillBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> SkillBuilder<()> {
                    SkillBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_version: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_input_schema: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_output_schema: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_preconditions: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<str>]>,
                    >,
                    field_postconditions: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<str>]>,
                    >,
                    field_criticality: impl ::planus::WriteAsDefault<
                        self::Criticality,
                        self::Criticality,
                    >,
                    field_fallback: impl ::planus::WriteAsOptional<
                        ::planus::Offset<::core::primitive::str>,
                    >,
                    field_evidence_required: impl ::planus::WriteAsDefault<bool, bool>,
                    field_evaluation_dataset: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_evaluation_thresholds: impl ::planus::WriteAs<::planus::Offset<str>>,
                    field_candidate_executors: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<str>]>,
                    >,
                    field_provenance_id: impl ::planus::WriteAs<::planus::Offset<str>>,
                ) -> ::planus::Offset<Self> {
                    let prepared_id = field_id.prepare(builder);
                    let prepared_version = field_version.prepare(builder);
                    let prepared_input_schema = field_input_schema.prepare(builder);
                    let prepared_output_schema = field_output_schema.prepare(builder);
                    let prepared_preconditions = field_preconditions.prepare(builder);
                    let prepared_postconditions = field_postconditions.prepare(builder);
                    let prepared_criticality =
                        field_criticality.prepare(builder, &self::Criticality::Low);
                    let prepared_fallback = field_fallback.prepare(builder);
                    let prepared_evidence_required =
                        field_evidence_required.prepare(builder, &false);
                    let prepared_evaluation_dataset = field_evaluation_dataset.prepare(builder);
                    let prepared_evaluation_thresholds =
                        field_evaluation_thresholds.prepare(builder);
                    let prepared_candidate_executors = field_candidate_executors.prepare(builder);
                    let prepared_provenance_id = field_provenance_id.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<30> =
                        ::core::default::Default::default();
                    table_writer.write_entry::<::planus::Offset<str>>(0);
                    table_writer.write_entry::<::planus::Offset<str>>(1);
                    table_writer.write_entry::<::planus::Offset<str>>(2);
                    table_writer.write_entry::<::planus::Offset<str>>(3);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<str>]>>(4);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<str>]>>(5);
                    if prepared_fallback.is_some() {
                        table_writer.write_entry::<::planus::Offset<str>>(7);
                    }
                    table_writer.write_entry::<::planus::Offset<str>>(9);
                    table_writer.write_entry::<::planus::Offset<str>>(10);
                    table_writer.write_entry::<::planus::Offset<[::planus::Offset<str>]>>(11);
                    table_writer.write_entry::<::planus::Offset<str>>(12);
                    if prepared_criticality.is_some() {
                        table_writer.write_entry::<self::Criticality>(6);
                    }
                    if prepared_evidence_required.is_some() {
                        table_writer.write_entry::<bool>(8);
                    }

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            object_writer.write::<_, _, 4>(&prepared_id);
                            object_writer.write::<_, _, 4>(&prepared_version);
                            object_writer.write::<_, _, 4>(&prepared_input_schema);
                            object_writer.write::<_, _, 4>(&prepared_output_schema);
                            object_writer.write::<_, _, 4>(&prepared_preconditions);
                            object_writer.write::<_, _, 4>(&prepared_postconditions);
                            if let ::core::option::Option::Some(prepared_fallback) =
                                prepared_fallback
                            {
                                object_writer.write::<_, _, 4>(&prepared_fallback);
                            }
                            object_writer.write::<_, _, 4>(&prepared_evaluation_dataset);
                            object_writer.write::<_, _, 4>(&prepared_evaluation_thresholds);
                            object_writer.write::<_, _, 4>(&prepared_candidate_executors);
                            object_writer.write::<_, _, 4>(&prepared_provenance_id);
                            if let ::core::option::Option::Some(prepared_criticality) =
                                prepared_criticality
                            {
                                object_writer.write::<_, _, 1>(&prepared_criticality);
                            }
                            if let ::core::option::Option::Some(prepared_evidence_required) =
                                prepared_evidence_required
                            {
                                object_writer.write::<_, _, 1>(&prepared_evidence_required);
                            }
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<Skill>> for Skill {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Skill> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<Skill>> for Skill {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<Skill>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<Skill> for Skill {
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Skill> {
                    Skill::create(
                        builder,
                        &self.id,
                        &self.version,
                        &self.input_schema,
                        &self.output_schema,
                        &self.preconditions,
                        &self.postconditions,
                        self.criticality,
                        &self.fallback,
                        self.evidence_required,
                        &self.evaluation_dataset,
                        &self.evaluation_thresholds,
                        &self.candidate_executors,
                        &self.provenance_id,
                    )
                }
            }

            /// Builder for serializing an instance of the [Skill] type.
            ///
            /// Can be created using the [Skill::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct SkillBuilder<State>(State);

            impl SkillBuilder<()> {
                /// Setter for the [`id` field](Skill#structfield.id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn id<T0>(self, value: T0) -> SkillBuilder<(T0,)>
                where
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    SkillBuilder((value,))
                }
            }

            impl<T0> SkillBuilder<(T0,)> {
                /// Setter for the [`version` field](Skill#structfield.version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn version<T1>(self, value: T1) -> SkillBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0,) = self.0;
                    SkillBuilder((v0, value))
                }
            }

            impl<T0, T1> SkillBuilder<(T0, T1)> {
                /// Setter for the [`input_schema` field](Skill#structfield.input_schema).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn input_schema<T2>(self, value: T2) -> SkillBuilder<(T0, T1, T2)>
                where
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1) = self.0;
                    SkillBuilder((v0, v1, value))
                }
            }

            impl<T0, T1, T2> SkillBuilder<(T0, T1, T2)> {
                /// Setter for the [`output_schema` field](Skill#structfield.output_schema).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn output_schema<T3>(self, value: T3) -> SkillBuilder<(T0, T1, T2, T3)>
                where
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2) = self.0;
                    SkillBuilder((v0, v1, v2, value))
                }
            }

            impl<T0, T1, T2, T3> SkillBuilder<(T0, T1, T2, T3)> {
                /// Setter for the [`preconditions` field](Skill#structfield.preconditions).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn preconditions<T4>(self, value: T4) -> SkillBuilder<(T0, T1, T2, T3, T4)>
                where
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                {
                    let (v0, v1, v2, v3) = self.0;
                    SkillBuilder((v0, v1, v2, v3, value))
                }
            }

            impl<T0, T1, T2, T3, T4> SkillBuilder<(T0, T1, T2, T3, T4)> {
                /// Setter for the [`postconditions` field](Skill#structfield.postconditions).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn postconditions<T5>(self, value: T5) -> SkillBuilder<(T0, T1, T2, T3, T4, T5)>
                where
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                {
                    let (v0, v1, v2, v3, v4) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5> SkillBuilder<(T0, T1, T2, T3, T4, T5)> {
                /// Setter for the [`criticality` field](Skill#structfield.criticality).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn criticality<T6>(
                    self,
                    value: T6,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6)>
                where
                    T6: ::planus::WriteAsDefault<self::Criticality, self::Criticality>,
                {
                    let (v0, v1, v2, v3, v4, v5) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, value))
                }

                /// Sets the [`criticality` field](Skill#structfield.criticality) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn criticality_as_default(
                    self,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, ::planus::DefaultValue)>
                {
                    self.criticality(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6)> {
                /// Setter for the [`fallback` field](Skill#structfield.fallback).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn fallback<T7>(
                    self,
                    value: T7,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)>
                where
                    T7: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, v6, value))
                }

                /// Sets the [`fallback` field](Skill#structfield.fallback) to null.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn fallback_as_null(self) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, ())> {
                    self.fallback(())
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7)> {
                /// Setter for the [`evidence_required` field](Skill#structfield.evidence_required).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn evidence_required<T8>(
                    self,
                    value: T8,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)>
                where
                    T8: ::planus::WriteAsDefault<bool, bool>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, v6, v7, value))
                }

                /// Sets the [`evidence_required` field](Skill#structfield.evidence_required) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn evidence_required_as_default(
                    self,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, ::planus::DefaultValue)>
                {
                    self.evidence_required(::planus::DefaultValue)
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8)> {
                /// Setter for the [`evaluation_dataset` field](Skill#structfield.evaluation_dataset).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn evaluation_dataset<T9>(
                    self,
                    value: T9,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
                where
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9>
                SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)>
            {
                /// Setter for the [`evaluation_thresholds` field](Skill#structfield.evaluation_thresholds).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn evaluation_thresholds<T10>(
                    self,
                    value: T10,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
                where
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>
                SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)>
            {
                /// Setter for the [`candidate_executors` field](Skill#structfield.candidate_executors).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn candidate_executors<T11>(
                    self,
                    value: T11,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
                where
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>
                SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)>
            {
                /// Setter for the [`provenance_id` field](Skill#structfield.provenance_id).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn provenance_id<T12>(
                    self,
                    value: T12,
                ) -> SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
                where
                    T12: ::planus::WriteAs<::planus::Offset<str>>,
                {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) = self.0;
                    SkillBuilder((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, value))
                }
            }

            impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>
                SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [Skill].
                #[inline]
                pub fn finish(self, builder: &mut ::planus::Builder) -> ::planus::Offset<Skill>
                where
                    Self: ::planus::WriteAsOffset<Skill>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T6: ::planus::WriteAsDefault<self::Criticality, self::Criticality>,
                    T7: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T8: ::planus::WriteAsDefault<bool, bool>,
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T12: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAs<::planus::Offset<Skill>>
                for SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                type Prepared = ::planus::Offset<Skill>;

                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Skill> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T6: ::planus::WriteAsDefault<self::Criticality, self::Criticality>,
                    T7: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T8: ::planus::WriteAsDefault<bool, bool>,
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T12: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOptional<::planus::Offset<Skill>>
                for SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                type Prepared = ::planus::Offset<Skill>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<Skill>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAs<::planus::Offset<str>>,
                    T1: ::planus::WriteAs<::planus::Offset<str>>,
                    T2: ::planus::WriteAs<::planus::Offset<str>>,
                    T3: ::planus::WriteAs<::planus::Offset<str>>,
                    T4: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T5: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T6: ::planus::WriteAsDefault<self::Criticality, self::Criticality>,
                    T7: ::planus::WriteAsOptional<::planus::Offset<::core::primitive::str>>,
                    T8: ::planus::WriteAsDefault<bool, bool>,
                    T9: ::planus::WriteAs<::planus::Offset<str>>,
                    T10: ::planus::WriteAs<::planus::Offset<str>>,
                    T11: ::planus::WriteAs<::planus::Offset<[::planus::Offset<str>]>>,
                    T12: ::planus::WriteAs<::planus::Offset<str>>,
                > ::planus::WriteAsOffset<Skill>
                for SkillBuilder<(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)>
            {
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> ::planus::Offset<Skill> {
                    let (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) = &self.0;
                    Skill::create(
                        builder, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12,
                    )
                }
            }

            /// Reference to a deserialized [Skill].
            #[derive(Copy, Clone)]
            pub struct SkillRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> SkillRef<'a> {
                /// Getter for the [`id` field](Skill#structfield.id).
                #[inline]
                pub fn id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(0, "Skill", "id")
                }

                /// Getter for the [`version` field](Skill#structfield.version).
                #[inline]
                pub fn version(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(1, "Skill", "version")
                }

                /// Getter for the [`input_schema` field](Skill#structfield.input_schema).
                #[inline]
                pub fn input_schema(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(2, "Skill", "input_schema")
                }

                /// Getter for the [`output_schema` field](Skill#structfield.output_schema).
                #[inline]
                pub fn output_schema(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(3, "Skill", "output_schema")
                }

                /// Getter for the [`preconditions` field](Skill#structfield.preconditions).
                #[inline]
                pub fn preconditions(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<&'a ::core::primitive::str>>,
                > {
                    self.0.access_required(4, "Skill", "preconditions")
                }

                /// Getter for the [`postconditions` field](Skill#structfield.postconditions).
                #[inline]
                pub fn postconditions(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<&'a ::core::primitive::str>>,
                > {
                    self.0.access_required(5, "Skill", "postconditions")
                }

                /// Getter for the [`criticality` field](Skill#structfield.criticality).
                #[inline]
                pub fn criticality(&self) -> ::planus::Result<self::Criticality> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(6, "Skill", "criticality")?
                            .unwrap_or(self::Criticality::Low),
                    )
                }

                /// Getter for the [`fallback` field](Skill#structfield.fallback).
                #[inline]
                pub fn fallback(
                    &self,
                ) -> ::planus::Result<::core::option::Option<&'a ::core::primitive::str>>
                {
                    self.0.access(7, "Skill", "fallback")
                }

                /// Getter for the [`evidence_required` field](Skill#structfield.evidence_required).
                #[inline]
                pub fn evidence_required(&self) -> ::planus::Result<bool> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(8, "Skill", "evidence_required")?
                            .unwrap_or(false),
                    )
                }

                /// Getter for the [`evaluation_dataset` field](Skill#structfield.evaluation_dataset).
                #[inline]
                pub fn evaluation_dataset(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(9, "Skill", "evaluation_dataset")
                }

                /// Getter for the [`evaluation_thresholds` field](Skill#structfield.evaluation_thresholds).
                #[inline]
                pub fn evaluation_thresholds(
                    &self,
                ) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(10, "Skill", "evaluation_thresholds")
                }

                /// Getter for the [`candidate_executors` field](Skill#structfield.candidate_executors).
                #[inline]
                pub fn candidate_executors(
                    &self,
                ) -> ::planus::Result<
                    ::planus::Vector<'a, ::planus::Result<&'a ::core::primitive::str>>,
                > {
                    self.0.access_required(11, "Skill", "candidate_executors")
                }

                /// Getter for the [`provenance_id` field](Skill#structfield.provenance_id).
                #[inline]
                pub fn provenance_id(&self) -> ::planus::Result<&'a ::core::primitive::str> {
                    self.0.access_required(12, "Skill", "provenance_id")
                }
            }

            impl<'a> ::core::fmt::Debug for SkillRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("SkillRef");
                    f.field("id", &self.id());
                    f.field("version", &self.version());
                    f.field("input_schema", &self.input_schema());
                    f.field("output_schema", &self.output_schema());
                    f.field("preconditions", &self.preconditions());
                    f.field("postconditions", &self.postconditions());
                    f.field("criticality", &self.criticality());
                    if let ::core::option::Option::Some(field_fallback) =
                        self.fallback().transpose()
                    {
                        f.field("fallback", &field_fallback);
                    }
                    f.field("evidence_required", &self.evidence_required());
                    f.field("evaluation_dataset", &self.evaluation_dataset());
                    f.field("evaluation_thresholds", &self.evaluation_thresholds());
                    f.field("candidate_executors", &self.candidate_executors());
                    f.field("provenance_id", &self.provenance_id());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<SkillRef<'a>> for Skill {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: SkillRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        id: ::core::convert::Into::into(value.id()?),
                        version: ::core::convert::Into::into(value.version()?),
                        input_schema: ::core::convert::Into::into(value.input_schema()?),
                        output_schema: ::core::convert::Into::into(value.output_schema()?),
                        preconditions: value.preconditions()?.to_vec_result()?,
                        postconditions: value.postconditions()?.to_vec_result()?,
                        criticality: ::core::convert::TryInto::try_into(value.criticality()?)?,
                        fallback: value.fallback()?.map(::core::convert::Into::into),
                        evidence_required: ::core::convert::TryInto::try_into(
                            value.evidence_required()?,
                        )?,
                        evaluation_dataset: ::core::convert::Into::into(
                            value.evaluation_dataset()?,
                        ),
                        evaluation_thresholds: ::core::convert::Into::into(
                            value.evaluation_thresholds()?,
                        ),
                        candidate_executors: value.candidate_executors()?.to_vec_result()?,
                        provenance_id: ::core::convert::Into::into(value.provenance_id()?),
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for SkillRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for SkillRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[SkillRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<Skill>> for Skill {
                type Value = ::planus::Offset<Skill>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<Skill>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for SkillRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[SkillRef]", "read_as_root", 0)
                    })
                }
            }

            /// The table `SkillBundle` in the namespace `D2I.Package`
            ///
            /// Generated from these locations:
            /// * Table `SkillBundle` in the file `schemas\flatbuffers\skills.fbs:28`
            #[derive(
                Clone,
                Debug,
                PartialEq,
                PartialOrd,
                Eq,
                Ord,
                Hash,
                ::serde::Serialize,
                ::serde::Deserialize,
            )]
            pub struct SkillBundle {
                /// The field `schema_version` in the table `SkillBundle`
                pub schema_version: u32,
                /// The field `skills` in the table `SkillBundle`
                pub skills: ::planus::alloc::vec::Vec<self::Skill>,
            }

            #[allow(clippy::derivable_impls)]
            impl ::core::default::Default for SkillBundle {
                fn default() -> Self {
                    Self {
                        schema_version: 0,
                        skills: ::core::default::Default::default(),
                    }
                }
            }

            impl SkillBundle {
                /// Creates a [SkillBundleBuilder] for serializing an instance of this table.
                #[inline]
                pub fn builder() -> SkillBundleBuilder<()> {
                    SkillBundleBuilder(())
                }

                #[allow(clippy::too_many_arguments)]
                pub fn create(
                    builder: &mut ::planus::Builder,
                    field_schema_version: impl ::planus::WriteAsDefault<u32, u32>,
                    field_skills: impl ::planus::WriteAs<
                        ::planus::Offset<[::planus::Offset<self::Skill>]>,
                    >,
                ) -> ::planus::Offset<Self> {
                    let prepared_schema_version = field_schema_version.prepare(builder, &0);
                    let prepared_skills = field_skills.prepare(builder);

                    let mut table_writer: ::planus::table_writer::TableWriter<8> =
                        ::core::default::Default::default();
                    if prepared_schema_version.is_some() {
                        table_writer.write_entry::<u32>(0);
                    }
                    table_writer
                        .write_entry::<::planus::Offset<[::planus::Offset<self::Skill>]>>(1);

                    unsafe {
                        table_writer.finish(builder, |object_writer| {
                            if let ::core::option::Option::Some(prepared_schema_version) =
                                prepared_schema_version
                            {
                                object_writer.write::<_, _, 4>(&prepared_schema_version);
                            }
                            object_writer.write::<_, _, 4>(&prepared_skills);
                        });
                    }
                    builder.current_offset()
                }
            }

            impl ::planus::WriteAs<::planus::Offset<SkillBundle>> for SkillBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<SkillBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl ::planus::WriteAsOptional<::planus::Offset<SkillBundle>> for SkillBundle {
                type Prepared = ::planus::Offset<Self>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<SkillBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl ::planus::WriteAsOffset<SkillBundle> for SkillBundle {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<SkillBundle> {
                    SkillBundle::create(builder, self.schema_version, &self.skills)
                }
            }

            /// Builder for serializing an instance of the [SkillBundle] type.
            ///
            /// Can be created using the [SkillBundle::builder] method.
            #[derive(Debug)]
            #[must_use]
            pub struct SkillBundleBuilder<State>(State);

            impl SkillBundleBuilder<()> {
                /// Setter for the [`schema_version` field](SkillBundle#structfield.schema_version).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version<T0>(self, value: T0) -> SkillBundleBuilder<(T0,)>
                where
                    T0: ::planus::WriteAsDefault<u32, u32>,
                {
                    SkillBundleBuilder((value,))
                }

                /// Sets the [`schema_version` field](SkillBundle#structfield.schema_version) to the default value.
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn schema_version_as_default(
                    self,
                ) -> SkillBundleBuilder<(::planus::DefaultValue,)> {
                    self.schema_version(::planus::DefaultValue)
                }
            }

            impl<T0> SkillBundleBuilder<(T0,)> {
                /// Setter for the [`skills` field](SkillBundle#structfield.skills).
                #[inline]
                #[allow(clippy::type_complexity)]
                pub fn skills<T1>(self, value: T1) -> SkillBundleBuilder<(T0, T1)>
                where
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Skill>]>>,
                {
                    let (v0,) = self.0;
                    SkillBundleBuilder((v0, value))
                }
            }

            impl<T0, T1> SkillBundleBuilder<(T0, T1)> {
                /// Finish writing the builder to get an [Offset](::planus::Offset) to a serialized [SkillBundle].
                #[inline]
                pub fn finish(
                    self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<SkillBundle>
                where
                    Self: ::planus::WriteAsOffset<SkillBundle>,
                {
                    ::planus::WriteAsOffset::prepare(&self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Skill>]>>,
                > ::planus::WriteAs<::planus::Offset<SkillBundle>>
                for SkillBundleBuilder<(T0, T1)>
            {
                type Prepared = ::planus::Offset<SkillBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<SkillBundle> {
                    ::planus::WriteAsOffset::prepare(self, builder)
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Skill>]>>,
                > ::planus::WriteAsOptional<::planus::Offset<SkillBundle>>
                for SkillBundleBuilder<(T0, T1)>
            {
                type Prepared = ::planus::Offset<SkillBundle>;

                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::core::option::Option<::planus::Offset<SkillBundle>> {
                    ::core::option::Option::Some(::planus::WriteAsOffset::prepare(self, builder))
                }
            }

            impl<
                    T0: ::planus::WriteAsDefault<u32, u32>,
                    T1: ::planus::WriteAs<::planus::Offset<[::planus::Offset<self::Skill>]>>,
                > ::planus::WriteAsOffset<SkillBundle> for SkillBundleBuilder<(T0, T1)>
            {
                #[inline]
                fn prepare(
                    &self,
                    builder: &mut ::planus::Builder,
                ) -> ::planus::Offset<SkillBundle> {
                    let (v0, v1) = &self.0;
                    SkillBundle::create(builder, v0, v1)
                }
            }

            /// Reference to a deserialized [SkillBundle].
            #[derive(Copy, Clone)]
            pub struct SkillBundleRef<'a>(::planus::table_reader::Table<'a>);

            impl<'a> SkillBundleRef<'a> {
                /// Getter for the [`schema_version` field](SkillBundle#structfield.schema_version).
                #[inline]
                pub fn schema_version(&self) -> ::planus::Result<u32> {
                    ::core::result::Result::Ok(
                        self.0
                            .access(0, "SkillBundle", "schema_version")?
                            .unwrap_or(0),
                    )
                }

                /// Getter for the [`skills` field](SkillBundle#structfield.skills).
                #[inline]
                pub fn skills(
                    &self,
                ) -> ::planus::Result<::planus::Vector<'a, ::planus::Result<self::SkillRef<'a>>>>
                {
                    self.0.access_required(1, "SkillBundle", "skills")
                }
            }

            impl<'a> ::core::fmt::Debug for SkillBundleRef<'a> {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    let mut f = f.debug_struct("SkillBundleRef");
                    f.field("schema_version", &self.schema_version());
                    f.field("skills", &self.skills());
                    f.finish()
                }
            }

            impl<'a> ::core::convert::TryFrom<SkillBundleRef<'a>> for SkillBundle {
                type Error = ::planus::Error;

                #[allow(unreachable_code)]
                fn try_from(value: SkillBundleRef<'a>) -> ::planus::Result<Self> {
                    ::core::result::Result::Ok(Self {
                        schema_version: ::core::convert::TryInto::try_into(
                            value.schema_version()?,
                        )?,
                        skills: value.skills()?.to_vec_result()?,
                    })
                }
            }

            impl<'a> ::planus::TableRead<'a> for SkillBundleRef<'a> {
                #[inline]
                fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::core::result::Result<Self, ::planus::errors::ErrorKind> {
                    ::core::result::Result::Ok(Self(::planus::table_reader::Table::from_buffer(
                        buffer, offset,
                    )?))
                }
            }

            impl<'a> ::planus::VectorReadInner<'a> for SkillBundleRef<'a> {
                type Error = ::planus::Error;
                const STRIDE: usize = 4;

                unsafe fn from_buffer(
                    buffer: ::planus::SliceWithStartOffset<'a>,
                    offset: usize,
                ) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(buffer, offset).map_err(|error_kind| {
                        error_kind.with_error_location(
                            "[SkillBundleRef]",
                            "get",
                            buffer.offset_from_start,
                        )
                    })
                }
            }

            /// # Safety
            /// The planus compiler generates implementations that initialize
            /// the bytes in `write_values`.
            unsafe impl ::planus::VectorWrite<::planus::Offset<SkillBundle>> for SkillBundle {
                type Value = ::planus::Offset<SkillBundle>;
                const STRIDE: usize = 4;
                #[inline]
                fn prepare(&self, builder: &mut ::planus::Builder) -> Self::Value {
                    ::planus::WriteAs::prepare(self, builder)
                }

                #[inline]
                unsafe fn write_values(
                    values: &[::planus::Offset<SkillBundle>],
                    bytes: *mut ::core::mem::MaybeUninit<u8>,
                    buffer_position: u32,
                ) {
                    let bytes = bytes as *mut [::core::mem::MaybeUninit<u8>; 4];
                    for (i, v) in ::core::iter::Iterator::enumerate(values.iter()) {
                        ::planus::WriteAsPrimitive::write(
                            v,
                            ::planus::Cursor::new(unsafe { &mut *bytes.add(i) }),
                            buffer_position - (Self::STRIDE * i) as u32,
                        );
                    }
                }
            }

            impl<'a> ::planus::ReadAsRoot<'a> for SkillBundleRef<'a> {
                fn read_as_root(slice: &'a [u8]) -> ::planus::Result<Self> {
                    ::planus::TableRead::from_buffer(
                        ::planus::SliceWithStartOffset {
                            buffer: slice,
                            offset_from_start: 0,
                        },
                        0,
                    )
                    .map_err(|error_kind| {
                        error_kind.with_error_location("[SkillBundleRef]", "read_as_root", 0)
                    })
                }
            }
        }
    }
}
