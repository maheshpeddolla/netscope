from dataclasses import dataclass

from netscope.models.drop_location import DropLocation


@dataclass
class Evidence:

    source: str

    metric: str

    value: str

    location: DropLocation

    confidence: int

    description: str