use google_datastore1::api::{ArrayValue, Entity, Key, LatLng};
use std::collections::HashMap;

use super::error::ConvertError;

#[derive(Debug, Clone)]
pub enum Value {
    BooleanValue(bool),
    IntegerValue(i64),
    DoubleValue(f64),
    KeyValue(Key),
    StringValue(String),
    BlobValue(Vec<u8>),
    GeoPointValue(f64, f64),
    EntityValue {
        key: Key,
        properties: HashMap<String, Value>,
    },
    ArrayValue(Vec<Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::BooleanValue(_) => "bool",
            Value::IntegerValue(_) => "integer",
            Value::DoubleValue(_) => "double",
            Value::KeyValue(_) => "key",
            Value::StringValue(_) => "string",
            Value::BlobValue(_) => "blob",
            Value::GeoPointValue(_, _) => "geopoint",
            Value::EntityValue { .. } => "entity",
            Value::ArrayValue(_) => "array",
        }
    }
}

pub trait IntoValue {
    fn into_value(self) -> Value;
}

pub trait FromValue: Sized {
    fn from_value(value: Value) -> Result<Self, ConvertError>;
}

/*
 * IntoValue implementations
 */

impl IntoValue for Value {
    fn into_value(self) -> Value {
        self
    }
}

impl IntoValue for String {
    fn into_value(self) -> Value {
        Value::StringValue(self)
    }
}

impl IntoValue for &str {
    fn into_value(self) -> Value {
        String::from(self).into_value()
    }
}

impl IntoValue for i8 {
    fn into_value(self) -> Value {
        Value::IntegerValue(self as i64)
    }
}

impl IntoValue for i16 {
    fn into_value(self) -> Value {
        Value::IntegerValue(self as i64)
    }
}

impl IntoValue for i32 {
    fn into_value(self) -> Value {
        Value::IntegerValue(self as i64)
    }
}

impl IntoValue for i64 {
    fn into_value(self) -> Value {
        Value::IntegerValue(self)
    }
}

impl IntoValue for f32 {
    fn into_value(self) -> Value {
        Value::DoubleValue(self as f64)
    }
}

impl IntoValue for f64 {
    fn into_value(self) -> Value {
        Value::DoubleValue(self)
    }
}

impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::BooleanValue(self)
    }
}

impl IntoValue for Key {
    fn into_value(self) -> Value {
        Value::KeyValue(self)
    }
}

impl IntoValue for Vec<u8> {
    fn into_value(self) -> Value {
        Value::BlobValue(self.to_vec())
    }
}

impl<T> IntoValue for Vec<T>
where
    T: IntoValue,
{
    fn into_value(self) -> Value {
        Value::ArrayValue(self.into_iter().map(IntoValue::into_value).collect())
    }
}

impl From<google_datastore1::api::Value> for Value {
    fn from(value: google_datastore1::api::Value) -> Value {
        if let Some(val) = value.boolean_value {
            Value::BooleanValue(val)
        } else if let Some(val) = value.integer_value {
            Value::IntegerValue(val)
        } else if let Some(val) = value.double_value {
            Value::DoubleValue(val)
        } else if let Some(val) = value.key_value {
            Value::KeyValue(val)
        } else if let Some(val) = value.string_value {
            Value::StringValue(val)
        } else if let Some(val) = value.blob_value {
            Value::BlobValue(val)
        } else if let Some(val) = value.geo_point_value {
            Value::GeoPointValue(
                val.latitude.unwrap_or_default(),
                val.longitude.unwrap_or_default(),
            )
        } else if let Some(val) = value.entity_value {
            Value::EntityValue {
                key: val.key.unwrap_or_default(),
                properties: val
                    .properties
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, Value::from(v)))
                    .collect(),
            }
        } else if let Some(val) = value.array_value {
            Value::ArrayValue(
                val.values
                    .unwrap_or_default()
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            )
        } else {
            unimplemented!()
        }
    }
}

impl IntoValue for google_datastore1::api::Value {
    fn into_value(self) -> Value {
        self.into()
    }
}

impl IntoValue for google_datastore1::api::Entity {
    fn into_value(self) -> Value {
        Value::EntityValue {
            key: self.key.unwrap_or_default(),
            properties: self
                .properties
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k, v.into_value()))
                .collect(),
        }
    }
}

/*
 * FromValue implementations
 */

impl FromValue for Value {
    fn from_value(value: Value) -> Result<Value, ConvertError> {
        Ok(value)
    }
}

impl FromValue for String {
    fn from_value(value: Value) -> Result<String, ConvertError> {
        match value {
            Value::StringValue(value) => Ok(value),
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("string"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for i64 {
    fn from_value(value: Value) -> Result<i64, ConvertError> {
        match value {
            Value::IntegerValue(value) => Ok(value),
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("integer"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for f64 {
    fn from_value(value: Value) -> Result<f64, ConvertError> {
        match value {
            Value::DoubleValue(value) => Ok(value),
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("double"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for bool {
    fn from_value(value: Value) -> Result<bool, ConvertError> {
        match value {
            Value::BooleanValue(value) => Ok(value),
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("bool"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for Key {
    fn from_value(value: Value) -> Result<Key, ConvertError> {
        match value {
            Value::KeyValue(value) => Ok(value),
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("key"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for Vec<u8> {
    fn from_value(value: Value) -> Result<Vec<u8>, ConvertError> {
        match value {
            Value::BlobValue(value) => Ok(value),
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("blob"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl<T> FromValue for Vec<T>
where
    T: FromValue,
{
    fn from_value(value: Value) -> Result<Vec<T>, ConvertError> {
        match value {
            Value::ArrayValue(values) => {
                let values = values
                    .into_iter()
                    .map(FromValue::from_value)
                    .collect::<Result<Vec<T>, ConvertError>>()?;
                Ok(values)
            }
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("array"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for Entity {
    fn from_value(value: Value) -> Result<Entity, ConvertError> {
        match value {
            Value::EntityValue { key, properties } => {
                let properties = properties
                    .into_iter()
                    .map(|(k, v)| {
                        let v = FromValue::from_value(v)?;
                        Ok((k, v))
                    })
                    .collect::<Result<HashMap<String, google_datastore1::api::Value>, ConvertError>>()?;
                Ok(Entity {
                    key: Some(key),
                    properties: Some(properties),
                })
            }
            _ => Err(ConvertError::UnexpectedPropertyType {
                expected: String::from("entity"),
                got: String::from(value.type_name()),
            }),
        }
    }
}

impl FromValue for google_datastore1::api::Value {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        let result = match value {
            Value::BooleanValue(val) => google_datastore1::api::Value {
                boolean_value: Some(val),
                ..Default::default()
            },
            Value::IntegerValue(val) => google_datastore1::api::Value {
                integer_value: Some(val),
                ..Default::default()
            },
            Value::DoubleValue(val) => google_datastore1::api::Value {
                double_value: Some(val),
                ..Default::default()
            },
            Value::KeyValue(val) => google_datastore1::api::Value {
                key_value: Some(val),
                ..Default::default()
            },
            Value::StringValue(val) => google_datastore1::api::Value {
                string_value: Some(val),
                ..Default::default()
            },
            Value::BlobValue(val) => google_datastore1::api::Value {
                blob_value: Some(val),
                ..Default::default()
            },
            Value::GeoPointValue(latitude, longitude) => google_datastore1::api::Value {
                geo_point_value: Some(LatLng {
                    latitude: Some(latitude),
                    longitude: Some(longitude),
                }),
                ..Default::default()
            },
            Value::EntityValue { key, properties } => {
                let properties = properties
                    .into_iter()
                    .map(|(k, v)| FromValue::from_value(v).map(|v| (k, v)))
                    .collect::<Result<HashMap<String, google_datastore1::api::Value>, ConvertError>>()?;
                google_datastore1::api::Value {
                    entity_value: Some(Entity {
                        key: Some(key),
                        properties: Some(properties),
                    }),
                    ..Default::default()
                }
            }
            Value::ArrayValue(val) => {
                let values = val
                    .into_iter()
                    .map(FromValue::from_value)
                    .collect::<Result<Vec<google_datastore1::api::Value>, ConvertError>>()?;
                google_datastore1::api::Value {
                    array_value: Some(ArrayValue {
                        values: Some(values),
                    }),
                    ..Default::default()
                }
            }
        };
        Ok(result)
    }
}
