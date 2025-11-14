from pydantic import BaseModel


class DataTypeMatch(BaseModel):
    function_id: int
    ea: int
    
