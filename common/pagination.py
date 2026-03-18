"""
Standard pagination for DjangoAuth API.

Referenced in settings/base.py as DEFAULT_PAGINATION_CLASS.
"""

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardResultsPagination(PageNumberPagination):
    """
    Pagination shape:

        {
            "success": true,
            "data": {
                "count": 100,
                "next": "...",
                "previous": "...",
                "results": [...]
            }
        }
    """

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response(
            {
                "success": True,
                "data": {
                    "count": self.page.paginator.count,
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "results": data,
                },
            }
        )

    def get_paginated_response_schema(self, schema):
        """For drf-spectacular schema generation."""
        return {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "data": {
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer"},
                        "next": {"type": "string", "nullable": True},
                        "previous": {"type": "string", "nullable": True},
                        "results": schema,
                    },
                },
            },
        }
