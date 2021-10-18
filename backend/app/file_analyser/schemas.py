from marshmallow import Schema, fields


class PostSearchSchema(Schema):
    s = fields.String()

post_search_schema = PostSearchSchema()