"""Skill loader for compliance detection skills."""

import importlib
import pkgutil
from pathlib import Path
from typing import Iterator

from .base import BaseSkill, PatternDefinition


def discover_skills() -> Iterator[BaseSkill]:
    """Discover and load all available skills.

    Scans the skills directory for subdirectories containing
    skill implementations and yields instantiated skill objects.

    Yields:
        Instantiated BaseSkill subclasses.
    """
    skills_dir = Path(__file__).parent

    for item in skills_dir.iterdir():
        if item.is_dir() and not item.name.startswith('_'):
            # Try to import the skill module
            module_name = f"policyvibes.skills.{item.name}"
            try:
                module = importlib.import_module(module_name)
                # Look for a get_skill() function or Skill class
                if hasattr(module, 'get_skill'):
                    skill = module.get_skill()
                    if isinstance(skill, BaseSkill):
                        yield skill
                elif hasattr(module, 'Skill'):
                    skill_class = getattr(module, 'Skill')
                    if isinstance(skill_class, type) and issubclass(skill_class, BaseSkill):
                        yield skill_class()
            except ImportError:
                # Skip directories that aren't valid skill modules
                pass


def load_all_skills() -> list[BaseSkill]:
    """Load all available skills.

    Returns:
        List of all discovered and instantiated skills.
    """
    return list(discover_skills())


__all__ = ['BaseSkill', 'PatternDefinition', 'discover_skills', 'load_all_skills']
