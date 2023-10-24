// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"sync"

	"github.com/awcullen/opcua/ua"
)

// ObjectTypeNode ...
type ObjectTypeNode struct {
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
	isAbstract         bool
}

var _ Node = (*ObjectTypeNode)(nil)

// NewObjectTypeNode ...
func NewObjectTypeNode(server *Server, nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, isAbstract bool) *ObjectTypeNode {
	return &ObjectTypeNode{
		server:             server,
		nodeID:             nodeID,
		nodeClass:          ua.NodeClassObjectType,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		isAbstract:         isAbstract,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *ObjectTypeNode) NodeID() ua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ObjectTypeNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ObjectTypeNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ObjectTypeNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ObjectTypeNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ObjectTypeNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ObjectTypeNode) UserRolePermissions(userIdentity any) []ua.RolePermissionType {
	filteredPermissions := []ua.RolePermissionType{}
	roles, err := n.server.GetRoles(userIdentity, "", "")
	if err != nil {
		return filteredPermissions
	}
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = n.server.RolePermissions()
	}
	for _, role := range roles {
		for _, rp := range rolePermissions {
			if rp.RoleID == role {
				filteredPermissions = append(filteredPermissions, rp)
			}
		}
	}
	return filteredPermissions
}

// References returns the References of this node.
func (n *ObjectTypeNode) References() []ua.Reference {
	n.RLock()
	defer n.RUnlock()
	return n.references
}

// SetReferences sets the References of the Variable.
func (n *ObjectTypeNode) SetReferences(value []ua.Reference) {
	n.Lock()
	defer n.Unlock()
	n.references = value
}

// IsAbstract returns the IsAbstract attribute of this node.
func (n *ObjectTypeNode) IsAbstract() bool {
	return n.isAbstract
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ObjectTypeNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDIsAbstract:
		return true
	default:
		return false
	}
}
