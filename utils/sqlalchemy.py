from enum import Enum
from typing import TypeVar

from sqlalchemy import Enum as SQLAlchemyEnum


EnumType = TypeVar("EnumType", bound=Enum)


def enum_value_type(enum_class: type[EnumType], *, length: int) -> SQLAlchemyEnum:
    """Create a VARCHAR-backed SQLAlchemy enum that persists member values.

    Args:
        enum_class: Enum class used by the model field.
        length: Maximum length of the persisted enum value.

    Returns:
        A non-native SQLAlchemy enum type that restores enum members on reads.
    """
    return SQLAlchemyEnum(
        enum_class,
        values_callable=lambda members: [str(member.value) for member in members],
        native_enum=False,
        create_constraint=False,
        validate_strings=True,
        length=length,
    )
