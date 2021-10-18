from marshmallow import Schema, fields


class PostEnrichmentCheckSchema(Schema):
    tasks = fields.List(fields.String())

post_enrichment_check_schema = PostEnrichmentCheckSchema()