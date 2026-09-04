// modules/rbac-assignments.bicep
// Reusable module for Azure RBAC role assignments.
// Deploy at the scope where the role should be assigned (subscription, resource group, or resource).

@description('Principal ID (object ID) to assign the role to.')
param principalId string

@description('Role Definition ID (built-in or custom). Use the full GUID, not the display name.')
param roleDefinitionId string

@description('Principal type. Use ServicePrincipal for managed identities.')
@allowed(['ServicePrincipal', 'User', 'Group', 'ForeignGroup', 'Device'])
param principalType string = 'ServicePrincipal'

@description('Optional description for the role assignment.')
param roleDescription string = ''

// Unique deterministic name based on scope + principal + role.
var roleAssignmentName = guid(resourceGroup().id, principalId, roleDefinitionId)

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: roleAssignmentName
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
    principalType: principalType
    description: roleDescription
  }
}

output roleAssignmentId string = roleAssignment.id
