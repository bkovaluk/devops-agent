# The deployment's own catalog, read by both functions at cold start through
# CATALOG_PARAMETER. Without catalog_json they run on the catalog bundled with the
# package, and the role reads no parameter at all.
resource "aws_ssm_parameter" "catalog" {
  count = var.catalog_json == null ? 0 : 1

  name        = local.catalog_parameter_name
  description = "The ${var.name_prefix} catalog for ${var.environment}."
  type        = "String"
  tier        = length(var.catalog_json) > 4096 ? "Advanced" : "Standard"
  value       = var.catalog_json

  tags = var.tags
}
