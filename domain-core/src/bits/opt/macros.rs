//! Macros for option types.
//!
//! These macros are only used to generate enums in the parent module.
//! They are here in a separate module to keep the parent tidy.

macro_rules! opt_types {
    ( $(
        $module:ident::{
            $( $opt:ident $( <$octets:ident> )* ),*
        };
    )* ) => {

        $( $( pub use self::$module::$opt; )* )*

        $( pub mod $module; )*

        //------------ AllOptData --------------------------------------------

        #[derive(Clone, Debug)]
        pub enum AllOptData<O: Octets> {
            $( $(
                $opt($module::$opt $(< $octets >)* ),
            )* )*
            Other(UnknownOptData<O>),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }

        //--- From

        $( $(
            impl<O: Octets> From<$opt $(< $octets >)*> for AllOptData<O> {
                fn from(value: $module::$opt $(< $octets >)*) -> Self {
                    AllOptData::$opt(value)
                }
            }
        )* )*

        
        //--- Compose

        impl<O: Octets> Compose for AllOptData<O> {
            fn compose_len(&self) -> usize {
                match self {
                    $( $(
                        &AllOptData::$opt(ref inner) => inner.compose_len(),
                    )* )*
                    &AllOptData::Other(ref inner) => inner.compose_len(),
                    &AllOptData::__Nonexhaustive(_) => unreachable!(),
                }
            }

            fn compose<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match self {
                    $( $(
                        &AllOptData::$opt(ref inner) => inner.compose(buf),
                    )* )*
                    &AllOptData::Other(ref inner) => inner.compose(buf),
                    &AllOptData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- OptData

        impl<O: Octets> OptData<O> for AllOptData<O> {
            type ParseErr = AllOptParseError;

            fn code(&self) -> OptionCode {
                match self {
                    $( $(
                        &AllOptData::$opt(_) => OptionCode::$opt,
                    )* )*
                    &AllOptData::Other(ref inner) => inner.code(),
                    &AllOptData::__Nonexhaustive(_) => unreachable!()
                }
            }

            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<O>,
                len: usize
            ) -> Result<Option<Self>, Self::ParseErr> {
                match code {
                    $( $(
                        OptionCode::$opt => {
                            Ok(Some(AllOptData::$opt(
                                $opt::parse_all(parser, len)
                                    .map_err(AllOptParseError::$opt)?
                            )))
                        }
                    )* )*
                    _ => {
                        Ok(UnknownOptData::parse_option(
                            code, parser, len
                        )?.map(AllOptData::Other))
                    }
                }
            }
        }


        //------------ AllOptParseError --------------------------------------

        #[derive(Clone, Debug, Eq, Fail, PartialEq)]
        pub enum AllOptParseError {
            $( $(
                #[fail(display="{}", _0)]
                $opt(<$opt as OptData>::ParseErr),
            )* )*
            #[fail(display="short buffer")]
            ShortBuf,
        }

        impl From<::bits::parse::ShortBuf> for AllOptParseError {
            fn from(_: ::bits::parse::ShortBuf) -> Self {
                AllOptParseError::ShortBuf
            }
        }
    }
}
