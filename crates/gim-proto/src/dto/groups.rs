use gim_common::{DeviceId, GroupId, UserId};
use serde::{Deserialize, Serialize};

/// `GroupKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Direct,
    Group,
}

/// `Group`: delivery-service view of a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub group_id: GroupId,
    pub kind: GroupKind,
    /// Current MLS epoch, advanced by accepted commits.
    pub epoch: u64,
    pub created_by_device_id: DeviceId,
    /// Unix milliseconds.
    pub created_at: i64,
    pub members: Vec<GroupMember>,
}

/// `GroupMember`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub device_id: DeviceId,
    pub user_id: UserId,
}

/// `GroupList`: `GET /v1/groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupList {
    pub groups: Vec<Group>,
}

/// `CreateGroupRequest`: `POST /v1/groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub kind: GroupKind,
    /// Other devices to add (0-500); the caller is always a member.
    pub member_device_ids: Vec<DeviceId>,
}

/// `AddMembersRequest`: `POST /v1/groups/{group_id}/members`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddMembersRequest {
    /// 1-500 devices.
    pub device_ids: Vec<DeviceId>,
}
