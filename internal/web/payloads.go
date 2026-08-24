package web

// payloadField is one JSON property a request body carries. The table below
// is what the OpenAPI document describes to integrators; until it existed the
// specification named no request bodies at all, so a client reading it could
// not tell what to send and an empty body was the only reasonable guess.
//
// TestRequestPayloadsMatchTheHandlers re-derives this from the handlers
// themselves and fails when the two disagree, so the description cannot drift
// away from what the server actually decodes.
type payloadField struct{ Name, Type string }

var requestPayloads = map[string][]payloadField{
	"PATCH /api/v1/change-requests/{id}":                               {{"answer", "string"}, {"status", "string"}},
	"PATCH /api/v1/me":                                                 {{"display_name", "string"}, {"email", "string"}, {"department", "string"}},
	"PATCH /api/v1/review-requests/{id}":                               {{"description", "string"}, {"reviewer_id", "string"}, {"approver_id", "string"}, {"planned_open_date", "string"}, {"business_criticality", "string"}},
	"PATCH /api/v1/security-controls/{id}":                             {{"code", "string"}, {"title", "string"}, {"description", "string"}, {"owner_id", "string"}},
	"PATCH /api/v1/templates/{id}":                                     {{"name", "string"}, {"description", "string"}, {"active", "bool"}},
	"PATCH /api/v1/templates/{id}/versions/{versionID}/items/{itemID}": {{"section", "string"}, {"control_id", "string"}, {"item_code", "string"}, {"category", "string"}, {"title", "string"}, {"question", "string"}, {"guide", "string"}, {"legal_basis", "string"}, {"example", "string"}, {"severity", "string"}, {"answer_type", "string"}, {"required", "bool"}, {"evidence_required", "bool"}, {"applicability_rule", "any"}, {"options", "any"}, {"sort_order", "int"}},
	"POST /api/v1/admin/settings/notification/test":                    {{"recipient", "string"}},
	"POST /api/v1/admin/settings/upload/test":                          {{"address", "string"}},
	"POST /api/v1/admin/settings/oidc/test":                            {{"issuer", "string"}},
	"POST /api/v1/admin/users":                                         {{"username", "string"}, {"display_name", "string"}, {"email", "string"}, {"department", "string"}, {"password", "string"}, {"roles", "[]string"}},
	"POST /api/v1/admin/users/{id}/active":                             {{"active", "bool"}},
	"POST /api/v1/admin/users/{id}/password":                           {{"password", "string"}},
	"POST /api/v1/auth/login":                                          {{"username", "string"}, {"password", "string"}, {"totp_code", "string"}},
	"POST /api/v1/me/api-keys":                                         {{"name", "string"}, {"scopes", "[]string"}, {"expires_at", "time.Time"}},
	"POST /api/v1/me/totp/disable":                                     {{"current_password", "string"}},
	"POST /api/v1/me/totp/enable":                                      {{"code", "string"}},
	"POST /api/v1/review-requests":                                     {{"service_name", "string"}, {"description", "string"}, {"service_type", "string"}, {"change_type", "string"}, {"builder_id", "string"}, {"developer_id", "string"}, {"operator_id", "string"}, {"department", "string"}, {"reviewer_id", "string"}, {"approver_id", "string"}, {"planned_open_date", "string"}, {"exposure", "string"}, {"has_admin_page", "bool"}, {"processes_personal_data", "bool"}, {"processes_credit_data", "bool"}, {"external_customer_service", "bool"}, {"uses_cloud", "bool"}, {"uses_docker", "bool"}, {"uses_kubernetes", "bool"}, {"external_integration", "bool"}, {"internet_access", "bool"}, {"business_criticality", "string"}, {"manual_rule_override_reason", "string"}},
	"POST /api/v1/review-requests/{id}/approve":                        {{"comment", "string"}},
	"POST /api/v1/review-requests/{id}/change-requests":                {{"item_id", "string"}, {"reason", "string"}, {"assignee_id", "string"}, {"due_date", "string"}},
	"POST /api/v1/review-requests/{id}/change-requests/bulk":           {{"item_ids", "[]string"}, {"reason", "string"}, {"assignee_id", "string"}, {"due_date", "string"}},
	"POST /api/v1/review-requests/{id}/complete-review":                {{"final_opinion", "string"}, {"final_result", "string"}},
	"POST /api/v1/review-requests/{id}/items/{itemID}/comments":        {{"body", "string"}},
	"POST /api/v1/review-requests/{id}/participants":                   {{"user_id", "string"}, {"role", "string"}},
	"POST /api/v1/review-requests/{id}/reject":                         {{"comment", "string"}},
	"POST /api/v1/review-requests/{id}/responses/bulk":                 {{"item_ids", "[]string"}, {"applicability", "string"}, {"self_assessment", "string"}, {"na_reason", "string"}, {"current_state", "string"}, {"action_plan", "string"}, {"assigned_to", "string"}, {"overwrite", "bool"}, {"assign_only", "bool"}},
	"POST /api/v1/review-results/{id}/follow-up":                       {{"action", "string"}, {"done", "bool"}, {"note", "string"}},
	"POST /api/v1/review-requests/{id}/review-results/bulk":            {{"item_ids", "[]string"}, {"result", "string"}, {"final_applicability", "string"}, {"evidence_adequacy", "string"}, {"opinion", "string"}, {"overwrite", "bool"}},
	"POST /api/v1/review-requests/{id}/rule-overrides":                 {{"action", "string"}, {"item_id", "string"}, {"source_item_id", "string"}, {"reason", "string"}},
	"POST /api/v1/security-controls":                                   {{"code", "string"}, {"title", "string"}, {"description", "string"}, {"owner_id", "string"}},
	"POST /api/v1/templates":                                           {{"name", "string"}, {"category", "string"}, {"description", "string"}, {"version", "string"}},
	"POST /api/v1/templates/rule-simulation":                           {{"service_name", "string"}, {"description", "string"}, {"service_type", "string"}, {"change_type", "string"}, {"builder_id", "string"}, {"developer_id", "string"}, {"operator_id", "string"}, {"department", "string"}, {"reviewer_id", "string"}, {"approver_id", "string"}, {"planned_open_date", "string"}, {"exposure", "string"}, {"has_admin_page", "bool"}, {"processes_personal_data", "bool"}, {"processes_credit_data", "bool"}, {"external_customer_service", "bool"}, {"uses_cloud", "bool"}, {"uses_docker", "bool"}, {"uses_kubernetes", "bool"}, {"external_integration", "bool"}, {"internet_access", "bool"}, {"business_criticality", "string"}, {"manual_rule_override_reason", "string"}},
	"POST /api/v1/templates/{id}/copy":                                 {{"name", "string"}},
	"POST /api/v1/templates/{id}/versions":                             {{"version", "string"}, {"change_note", "string"}, {"base_version_id", "string"}},
	"POST /api/v1/templates/{id}/versions/{versionID}/items":           {{"section", "string"}, {"control_id", "string"}, {"item_code", "string"}, {"category", "string"}, {"title", "string"}, {"question", "string"}, {"guide", "string"}, {"legal_basis", "string"}, {"example", "string"}, {"severity", "string"}, {"answer_type", "string"}, {"required", "bool"}, {"evidence_required", "bool"}, {"applicability_rule", "any"}, {"options", "any"}, {"sort_order", "int"}},
	"PUT /api/v1/admin/users/{id}/roles":                               {{"roles", "[]string"}},
	"PUT /api/v1/me/notification-preferences":                          {{"email_enabled", "bool"}, {"digest", "string"}, {"muted_events", "[]string"}},
	"PUT /api/v1/me/password":                                          {{"current_password", "string"}, {"new_password", "string"}},
	"PUT /api/v1/review-requests/{id}/responses/{itemID}":              {{"answer", "any"}, {"applicability", "string"}, {"self_assessment", "string"}, {"current_state", "string"}, {"na_reason", "string"}, {"action_plan", "string"}, {"assigned_to", "string"}, {"expected_updated_at", "string"}},
	"PUT /api/v1/review-requests/{id}/review-results/{itemID}":         {{"final_applicability", "string"}, {"result", "string"}, {"opinion", "string"}, {"evidence_adequacy", "string"}, {"follow_up", "string"}, {"follow_up_due_date", "string"}, {"na_approved", "bool"}, {"expected_updated_at", "string"}},
}

// objectScopedRoutes need no particular role, but they are not open to every
// signed-in user either: the handler checks that the caller is a participant
// in that specific review, or may see that specific piece of evidence. An
// empty x-required-roles alone would tell an integrator the opposite.
//
// /mcp is left out deliberately. Its tools are scoped the same way, but the
// endpoint itself is JSON-RPC, so the flag would describe the transport
// rather than the call.
//
// TestObjectScopedRoutesMatchTheHandlers re-derives this from the handlers.
var objectScopedRoutes = map[string]bool{
	"POST /api/v1/review-results/{id}/follow-up":                 true,
	"POST /api/v1/review-requests/{id}/review-results/bulk":      true,
	"DELETE /api/v1/evidences/{id}":                              true,
	"GET /api/v1/evidences/{id}/download":                        true,
	"GET /api/v1/review-requests/{id}":                           true,
	"GET /api/v1/review-requests/{id}/export/{format}":           true,
	"GET /api/v1/review-requests/{id}/completion-check":          true,
	"GET /api/v1/review-requests/{id}/submission-check":          true,
	"GET /api/v1/review-requests/{id}/history":                   true,
	"GET /api/v1/review-requests/{id}/items":                     true,
	"PATCH /api/v1/change-requests/{id}":                         true,
	"PATCH /api/v1/review-requests/{id}":                         true,
	"GET /api/v1/evidences/{id}/versions":                        true,
	"POST /api/v1/evidences/{id}/versions":                       true,
	"POST /api/v1/review-requests/{id}/change-requests":          true,
	"POST /api/v1/review-requests/{id}/change-requests/bulk":     true,
	"POST /api/v1/review-requests/{id}/complete-review":          true,
	"POST /api/v1/review-requests/{id}/copy":                     true,
	"POST /api/v1/review-requests/{id}/items/{itemID}/comments":  true,
	"POST /api/v1/review-requests/{id}/items/{itemID}/evidences": true,
	"DELETE /api/v1/review-requests/{id}/participants/{userID}":  true,
	"GET /api/v1/review-requests/{id}/participants":              true,
	"POST /api/v1/review-requests/{id}/participants":             true,
	"POST /api/v1/review-requests/{id}/responses/bulk":           true,
	"POST /api/v1/review-requests/{id}/submit":                   true,
	"PUT /api/v1/review-requests/{id}/responses/{itemID}":        true,
	"PUT /api/v1/review-requests/{id}/review-results/{itemID}":   true,
}
