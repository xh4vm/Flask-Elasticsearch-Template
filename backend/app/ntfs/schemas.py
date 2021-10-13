from marshmallow import Schema, fields


class PostHashSchema(Schema):
    fingerprint = fields.Dict(keys=fields.String(), values=fields.String(), required=True)
    trusted = fields.Integer(required=True)
    hashes = fields.Dict(keys=fields.String(), values=fields.String(), required=True)
    path = fields.String(required=True)
    creation_time = fields.String(required=True)
    last_write_time = fields.String(required=True)

post_hash_schema = PostHashSchema()