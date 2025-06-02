import json
import reccmp.project.config as config

projectFile = config.ProjectFile(targets={})
userFile = config.UserFile(targets={})
buildFile = config.BuildFile(project="", targets={})

projectSchema = projectFile.model_json_schema(by_alias=False)
projectSchema["$schema"] = "http://json-schema.org/draft-07/schema#"

userSchema = userFile.model_json_schema(by_alias=False)
userSchema["$schema"] = "http://json-schema.org/draft-07/schema#"

buildSchema = buildFile.model_json_schema(by_alias=False)
buildSchema["$schema"] = "http://json-schema.org/draft-07/schema#"

with open("project-schema.json", "wt", encoding="utf-8") as schema:
    schema.write(json.dumps(projectSchema, indent=2))

with open("user-schema.json", "wt", encoding="utf-8") as schema:
    schema.write(json.dumps(userSchema, indent=2))

with open("build-schema.json", "wt", encoding="utf-8") as schema:
    schema.write(json.dumps(buildSchema, indent=2))
