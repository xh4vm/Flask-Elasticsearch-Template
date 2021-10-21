import json
# from app import 


# @app.template_filter()
def fromjson(s : str):
    try:
        return  json.loads(s)
    except:
        return None