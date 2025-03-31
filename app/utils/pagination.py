"""
Pagination utilities for the Password Manager application.

This module provides helper classes and functions to handle pagination
for database results and other collections.
"""

from flask import request, url_for, abort
from math import ceil


class Pagination:
    """
    A class to handle pagination for database queries or other collections.
    """
    
    def __init__(self, items, page=None, per_page=None, total=None, endpoint=None, **kwargs):
        """
        Initialize a pagination object.
        
        Args:
            items: The items for the current page
            page (int): Current page number (1-indexed)
            per_page (int): Number of items per page
            total (int): Total number of items
            endpoint (str): The endpoint for generating page URLs
            **kwargs: Additional arguments to pass to url_for
        """
        self.items = items
        self.page = page or 1
        self.per_page = per_page or 10
        self.total = total or len(items)
        self.endpoint = endpoint
        self.kwargs = kwargs
    
    @property
    def pages(self):
        """
        The total number of pages.
        """
        if self.per_page == 0 or self.total == 0:
            return 0
        return int(ceil(self.total / float(self.per_page)))
    
    @property
    def has_prev(self):
        """
        True if a previous page exists.
        """
        return self.page > 1
    
    @property
    def has_next(self):
        """
        True if a next page exists.
        """
        return self.page < self.pages
    
    @property
    def prev_num(self):
        """
        Number of the previous page.
        """
        if not self.has_prev:
            return None
        return self.page - 1
    
    @property
    def next_num(self):
        """
        Number of the next page.
        """
        if not self.has_next:
            return None
        return self.page + 1
    
    def iter_pages(self, left_edge=2, left_current=2, right_current=5, right_edge=2):
        """
        Iterates over the page numbers in the pagination.
        
        Args:
            left_edge (int): Number of pages at the beginning
            left_current (int): Number of pages before current page
            right_current (int): Number of pages after current page
            right_edge (int): Number of pages at the end
            
        Returns:
            generator: Page numbers as iterator
        """
        last = 0
        for num in range(1, self.pages + 1):
            if (num <= left_edge or
                (self.page - left_current - 1 < num < self.page + right_current) or
                num > self.pages - right_edge):
                if last + 1 != num:
                    yield None
                yield num
                last = num
    
    def url_for_page(self, page):
        """
        Generate URL for the specified page.
        
        Args:
            page (int): Page number
            
        Returns:
            str: URL for the page
        """
        if self.endpoint is None:
            return None
            
        kwargs = dict(self.kwargs)
        if page != 1:
            kwargs['page'] = page
        elif 'page' in kwargs:
            del kwargs['page']
        
        return url_for(self.endpoint, **kwargs)


def paginate(query, page=None, per_page=None, error_out=True, max_per_page=None):
    """
    Paginate a SQLAlchemy query object.
    
    Args:
        query: SQLAlchemy query object
        page (int): Page number (1-indexed)
        per_page (int): Number of items per page
        error_out (bool): Abort with 404 if page or per_page is invalid
        max_per_page (int): Maximum number of items per page
        
    Returns:
        Pagination: A Pagination object
    """
    if page is None:
        page = request.args.get('page', 1, type=int)
    if per_page is None:
        per_page = request.args.get('per_page', 10, type=int)
    
    # Ensure per_page doesn't exceed max_per_page
    if max_per_page is not None:
        per_page = min(per_page, max_per_page)
    
    # Ensure page and per_page are valid
    if page < 1:
        if error_out:
            abort(404)
        page = 1
    
    if per_page < 1:
        if error_out:
            abort(404)
        per_page = 10
    
    # Execute query with pagination
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    
    # Handle empty result
    if not items and page != 1 and error_out:
        abort(404)
    
    # Get total count without pagination
    total = query.order_by(None).count()
    
    # Create Pagination object
    return Pagination(items, page=page, per_page=per_page, total=total,
                     endpoint=request.endpoint, **dict(request.args))


def paginate_list(items, page=None, per_page=None, error_out=True):
    """
    Paginate a list or other sequence.
    
    Args:
        items (list): List of items to paginate
        page (int): Page number (1-indexed)
        per_page (int): Number of items per page
        error_out (bool): Abort with 404 if page is invalid
        
    Returns:
        Pagination: A Pagination object
    """
    if page is None:
        page = request.args.get('page', 1, type=int)
    if per_page is None:
        per_page = request.args.get('per_page', 10, type=int)
    
    # Ensure page is valid
    if page < 1:
        if error_out:
            abort(404)
        page = 1
    
    if per_page < 1:
        if error_out:
            abort(404)
        per_page = 10
    
    # Calculate offset and limit
    offset = (page - 1) * per_page
    limit = offset + per_page
    
    # Get items for current page
    paged_items = items[offset:limit]
    
    # Handle empty result
    if not paged_items and page != 1 and error_out:
        abort(404)
    
    # Create Pagination object
    return Pagination(paged_items, page=page, per_page=per_page, total=len(items),
                     endpoint=request.endpoint, **dict(request.args)) 