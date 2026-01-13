# Define the schema for a single Fact object
fact_schema = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string", 
            # អនុញ្ញាតឱ្យអក្សរខ្មែរ, ឡាតាំង, លេខ, និង underscore
            "pattern": "^[a-zA-Z0-9_\u1780-\u17FF\u17E0-\u17E9]+$"
        },
        "description": {"type": "string"},
        "value": {"type": "boolean"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "category": {"type": "string"}
        
    },
    "required": ["id", "description", "value", "tags"],
    "additionalProperties": False
}

# Define the schema for the array of Facts
facts_array_schema = {
    "type": "array",
    "items": fact_schema
}

# Define the schema for a single Rule object

rule_schema = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string", 
            "pattern": "^[a-zA-Z0-9_\u1780-\u17FF\u17E0-\u17E9\\s]+$"
        },
        "conditions": {"type": "array", "items": {"type": "string"}},
        "conclusion": {
            "type": "string", 
            "pattern": "^[a-zA-Z0-9_\u1780-\u17FF\u17E0-\u17E9\\s]+$"
        },
        "certainty": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "explain": {"type": "string"},
        "recommendation": {"type": "string"}
    },
    "required": ["id", "conditions", "conclusion", "certainty", "explain"],
    "additionalProperties": False
}

# Define the schema for the array of Rules
rules_array_schema = {
    "type": "array",
    "items": rule_schema
}