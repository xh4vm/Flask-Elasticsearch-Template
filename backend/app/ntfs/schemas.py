from marshmallow import Schema, fields


class PostHashSchema(Schema):
    path = fields.String(required=True)
    md5_hash = fields.String(required=True)
    creation_time = fields.String(required=True)
    last_write_time = fields.String(required=True)

post_hash_schema = PostHashSchema()