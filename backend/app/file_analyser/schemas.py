from marshmallow import Schema, fields


class PostSearchSchema(Schema):
    s = fields.String(required=True)
    search_type = fields.String(required=True)
    # search_obj = fields.String(required=True)
    search_obj = fields.List(fields.String(required=True))

class GetSearchSchema(Schema):
    s = fields.String(required=False)
    search_type = fields.String(required=False)
    # search_obj = fields.String(required=True)
    search_obj = fields.String(required=False)

class PostSearchTypeSchema(Schema):
    search_type = fields.String(required=False)


post_search_schema = PostSearchSchema()
get_search_schema = GetSearchSchema()
post_search_type_schema = PostSearchTypeSchema()