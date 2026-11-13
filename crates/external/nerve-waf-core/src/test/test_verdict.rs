use crate::WafAction;

#[test]
fn waf_action_roundtrip_str() {
    assert_eq!(WafAction::Block.as_str(), "block");
    assert_eq!(WafAction::from_l7_action("block"), WafAction::Block);
    assert_eq!(WafAction::from_l7_action("detect"), WafAction::Log);
    assert_eq!(WafAction::from_l7_action("allow"), WafAction::Allow);
}
