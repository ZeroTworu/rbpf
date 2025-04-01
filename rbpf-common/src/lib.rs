#![no_std]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub source_addr_v6: u128,
    pub destination_addr_v6: u128,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port_start: u16,
    pub source_port_end: u16,
    pub destination_port_start: u16,
    pub destination_port_end: u16,

    pub input: bool,
    pub output: bool,

    pub source_mask_v4: u8,
    pub destination_mask_v4: u8,
    pub source_mask_v6: u8,
    pub destination_mask_v6: u8,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LogMessage {
    pub message: [u8; 128],
    pub input: bool,
    pub output: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub src_ip_high: u64,
    pub src_ip_low: u64,
    pub dst_ip_high: u64,
    pub dst_ip_low: u64,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port: u16,
    pub destination_port: u16,

    pub level: u8,
}

#[cfg(feature = "user")]
pub mod user {
    extern crate alloc;
    use super::*;
    use alloc::boxed::Box;
    use core::fmt;
    use core::iter;
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use poem_openapi::registry::{MetaSchema, MetaSchemaRef};
    use poem_openapi::types::{ParseFromJSON, ParseResult, ToJSON, Type};
    use serde_json::Value;

    impl Type for Rule {
        const IS_REQUIRED: bool = true;

        type RawValueType = Self;
        type RawElementValueType = Self;

        fn name() -> alloc::borrow::Cow<'static, str> {
            alloc::borrow::Cow::Borrowed("Rule")
        }

        fn schema_ref() -> MetaSchemaRef {
            MetaSchemaRef::Inline(Box::new(MetaSchema::new("Rule")))
        }
        fn as_raw_value(&self) -> Option<&Self::RawValueType> {
            Some(self)
        }

        fn raw_element_iter<'a>(
            &'a self,
        ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a> {
            Box::new(iter::once(self))
        }
    }

    impl ToJSON for Rule {
        fn to_json(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({
                "drop": self.drop,
                "ok": self.ok,
                "v4": self.v4,
                "v6": self.v6,
                "tcp": self.tcp,
                "udp": self.udp,
                "source_addr_v6": self.source_addr_v6,
                "destination_addr_v6": self.destination_addr_v6,
                "source_addr_v4": self.source_addr_v4,
                "destination_addr_v4": self.destination_addr_v4,
                "rule_id": self.rule_id,
                "ifindex": self.ifindex,
                "source_port_start": self.source_port_start,
                "source_port_end": self.source_port_end,
                "destination_port_start": self.destination_port_start,
                "destination_port_end": self.destination_port_end,
                "input": self.input,
                "output": self.output,
                "source_mask_v4": self.source_mask_v4,
                "destination_mask_v4": self.destination_mask_v4,
                "source_mask_v6": self.source_mask_v6,
                "destination_mask_v6": self.destination_mask_v6
            }))
        }
    }

    impl ParseFromJSON for Rule {
        fn parse_from_json(value: Option<Value>) -> ParseResult<Self> {
            if let Some(value) = value {
                serde_json::from_value(value)
                    .map_err(|_| poem_openapi::types::ParseError::custom("Invalid Rule format"))
            } else {
                Err(poem_openapi::types::ParseError::custom(
                    "Expected JSON object",
                ))
            }
        }
    }

    unsafe impl aya::Pod for LogMessage {}
    unsafe impl aya::Pod for Rule {}
    impl Serialize for Rule {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut s = serializer.serialize_struct("Rule", 22)?;
            s.serialize_field("drop", &self.drop)?;
            s.serialize_field("ok", &self.ok)?;
            s.serialize_field("v4", &self.v4)?;
            s.serialize_field("v6", &self.v6)?;
            s.serialize_field("tcp", &self.tcp)?;
            s.serialize_field("udp", &self.udp)?;

            s.serialize_field("source_addr_v6", &self.source_addr_v6.to_be_bytes())?;
            s.serialize_field(
                "destination_addr_v6",
                &self.destination_addr_v6.to_be_bytes(),
            )?;
            s.serialize_field("source_addr_v4", &self.source_addr_v4)?;
            s.serialize_field("destination_addr_v4", &self.destination_addr_v4)?;
            s.serialize_field("rule_id", &self.rule_id)?;
            s.serialize_field("ifindex", &self.ifindex)?;

            s.serialize_field("source_port_start", &self.source_port_start)?;
            s.serialize_field("source_port_end", &self.source_port_end)?;
            s.serialize_field("destination_port_start", &self.destination_port_start)?;
            s.serialize_field("destination_port_end", &self.destination_port_end)?;

            s.serialize_field("input", &self.input)?;
            s.serialize_field("output", &self.output)?;

            s.serialize_field("source_mask_v4", &self.source_mask_v4)?;
            s.serialize_field("destination_mask_v4", &self.destination_mask_v4)?;
            s.serialize_field("source_mask_v6", &self.source_mask_v6)?;
            s.serialize_field("destination_mask_v6", &self.destination_mask_v6)?;

            s.end()
        }
    }

    impl<'de> Deserialize<'de> for Rule {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct RuleVisitor;

            impl<'de> Visitor<'de> for RuleVisitor {
                type Value = Rule;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("struct Rule")
                }

                fn visit_seq<V>(self, mut seq: V) -> Result<Rule, V::Error>
                where
                    V: SeqAccess<'de>,
                {
                    Ok(Rule {
                        drop: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("drop"))?,
                        ok: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("ok"))?,
                        v4: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("v4"))?,
                        v6: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("v6"))?,
                        tcp: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("tcp"))?,
                        udp: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("udp"))?,

                        source_addr_v6: u128::from_be_bytes(
                            seq.next_element()?
                                .ok_or_else(|| de::Error::missing_field("source_addr_v6"))?,
                        ),
                        destination_addr_v6: u128::from_be_bytes(
                            seq.next_element()?
                                .ok_or_else(|| de::Error::missing_field("destination_addr_v6"))?,
                        ),
                        source_addr_v4: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("source_addr_v4"))?,
                        destination_addr_v4: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("destination_addr_v4"))?,
                        rule_id: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("rule_id"))?,
                        ifindex: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("ifindex"))?,

                        source_port_start: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("source_port_start"))?,
                        source_port_end: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("source_port_end"))?,
                        destination_port_start: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("destination_port_start"))?,
                        destination_port_end: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("destination_port_end"))?,

                        input: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("input"))?,
                        output: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("output"))?,

                        source_mask_v4: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("source_mask_v4"))?,
                        destination_mask_v4: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("destination_mask_v4"))?,
                        source_mask_v6: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("source_mask_v6"))?,
                        destination_mask_v6: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::missing_field("destination_mask_v6"))?,
                    })
                }
            }

            deserializer.deserialize_seq(RuleVisitor)
        }
    }
}
