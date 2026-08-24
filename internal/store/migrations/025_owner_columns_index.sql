-- Every list a person sees is filtered by the columns that name them on a
-- review. The requester, reviewer and approver columns were indexed from the
-- start; the three service owners the form asks for were not, so a builder,
-- developer or operator opening their own list made the database read the
-- whole table.
CREATE INDEX IF NOT EXISTS idx_review_requests_builder ON review_requests(builder_id);
CREATE INDEX IF NOT EXISTS idx_review_requests_developer ON review_requests(developer_id);
CREATE INDEX IF NOT EXISTS idx_review_requests_operator ON review_requests(operator_id);
