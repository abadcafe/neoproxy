use crate::config::SerializedArgs;

pub(crate) fn empty_args() -> SerializedArgs {
  serde_yaml::from_str(r#"{}"#).unwrap()
}
