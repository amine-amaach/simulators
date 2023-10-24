// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"sync"

	"github.com/awcullen/opcua/ua"
)

// MethodNode is a Node class that describes the syntax of a object's Method.
type MethodNode struct {
	sync.RWMutex
	server             *Server
	nodeID             ua.NodeID
	nodeClass          ua.NodeClass
	browseName         ua.QualifiedName
	displayName        ua.LocalizedText
	description        ua.LocalizedText
	rolePermissions    []ua.RolePermissionType
	accessRestrictions uint16
	references         []ua.Reference
	executable         bool
	callMethodHandler  func(*Session, ua.CallMethodRequest) ua.CallMethodResult
}

var _ Node = (*MethodNode)(nil)

// NewMethodNode constructs a new MethodNode.
func NewMethodNode(server *Server, nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, executable bool) *MethodNode {
	return &MethodNode{
		server:             server,
		nodeID:             nodeID,
		nodeClass:          ua.NodeClassMethod,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		executable:         executable,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *MethodNode) NodeID() ua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *MethodNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *MethodNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *MethodNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *MethodNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *MethodNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *MethodNode) UserRolePermissions(userIdentity any) []ua.RolePermissionType {
	filteredPermissions := []ua.RolePermissionType{}
	roles, err := n.server.GetRoles(userIdentity, "", "")
	if err != nil {
		return filteredPermissions
	}
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = n.server.RolePermissions()
	}
	for _, rp := range rolePermissions {
		for _, r := range roles {
			if rp.RoleID == r {
				filteredPermissions = append(filteredPermissions, rp)
			}
		}
	}
	return filteredPermissions
}

// References returns the References of this node.
func (n *MethodNode) References() []ua.Reference {
	n.RLock()
	defer n.RUnlock()
	return n.references
}

// SetReferences sets the References of the Variable.
func (n *MethodNode) SetReferences(value []ua.Reference) {
	n.Lock()
	defer n.Unlock()
	n.references = value
}

// Executable returns the Executable attribute of this node.
func (n *MethodNode) Executable() bool {
	return n.executable
}

// UserExecutable returns the UserExecutable attribute of this node.
func (n *MethodNode) UserExecutable(userIdentity any) bool {
	if !n.executable {
		return false
	}
	roles, err := n.server.GetRoles(userIdentity, "", "")
	if err != nil {
		return false
	}
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = n.server.RolePermissions()
	}
	for _, role := range roles {
		for _, rp := range rolePermissions {
			if rp.RoleID == role && rp.Permissions&ua.PermissionTypeCall != 0 {
				return true
			}
		}
	}
	return false
}

// SetCallMethodHandler sets the CallMethod of the Variable.
func (n *MethodNode) SetCallMethodHandler(value func(*Session, ua.CallMethodRequest) ua.CallMethodResult) {
	n.Lock()
	defer n.Unlock()
	n.callMethodHandler = value
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *MethodNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDExecutable, ua.AttributeIDUserExecutable:
		return true
	default:
		return false
	}
}
