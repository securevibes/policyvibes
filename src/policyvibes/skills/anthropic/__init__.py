"""Anthropic OAuth abuse detection skill."""

from .patterns import AnthropicOAuthSkill


def get_skill() -> AnthropicOAuthSkill:
    """Return an instance of the Anthropic OAuth skill."""
    return AnthropicOAuthSkill()


Skill = AnthropicOAuthSkill

__all__ = ['AnthropicOAuthSkill', 'get_skill', 'Skill']
