from marshmallow import Schema, fields


class PostEnrichmentCheckSchema(Schema):
    tasks = fields.List(fields.String(required=True), required=True)

post_enrichment_check_schema = PostEnrichmentCheckSchema()