package eu.starsong.ghidra.hateoas;

import eu.starsong.ghidra.server.GhidraContext.Pagination;

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * Utility class for paginating collections and generating HATEOAS pagination links.
 */
public class Paginator {

    private Paginator() {
    }

    /**
     * Paginate a list of items and return a paginated result.
     *
     * @param items      The full list of items
     * @param pagination The pagination parameters
     * @param basePath   The base path for generating links
     * @param <T>        The type of items
     * @return A paginated result with items and metadata
     */
    public static <T> PaginatedResult<T> paginate(List<T> items, Pagination pagination, String basePath) {
        return paginate(items, pagination.offset(), pagination.limit(), basePath);
    }

    /**
     * Paginate a list of items and return a paginated result.
     *
     * @param items    The full list of items
     * @param offset   The starting offset
     * @param limit    The maximum number of items
     * @param basePath The base path for generating links
     * @param <T>      The type of items
     * @return A paginated result with items and metadata
     */
    public static <T> PaginatedResult<T> paginate(List<T> items, int offset, int limit, String basePath) {
        if (items == null || items.isEmpty()) {
            return new PaginatedResult<>(Collections.emptyList(), 0, offset, limit, basePath);
        }

        int total = items.size();
        int start = Math.max(0, Math.min(offset, total));
        int end = Math.min(total, start + limit);

        List<T> pageItems = start < end ? items.subList(start, end) : Collections.emptyList();

        return new PaginatedResult<>(pageItems, total, offset, limit, basePath);
    }

    /**
     * Paginate a list and transform items to a different type.
     *
     * @param items      The full list of items
     * @param pagination The pagination parameters
     * @param basePath   The base path for generating links
     * @param mapper     Function to transform each item
     * @param <T>        The source item type
     * @param <R>        The target item type
     * @return A paginated result with transformed items
     */
    public static <T, R> PaginatedResult<R> paginateAndMap(
            List<T> items,
            Pagination pagination,
            String basePath,
            Function<T, R> mapper) {

        PaginatedResult<T> paginated = paginate(items, pagination, basePath);
        List<R> mapped = paginated.items().stream().map(mapper).toList();

        return new PaginatedResult<>(mapped, paginated.total(), pagination.offset(), pagination.limit(), basePath);
    }

    /**
     * Apply additional query parameters to pagination links.
     *
     * @param basePath    The base path
     * @param queryParams Additional query parameters (without leading &)
     * @return The base path with query parameters
     */
    public static String withQueryParams(String basePath, String queryParams) {
        if (queryParams == null || queryParams.isEmpty()) {
            return basePath;
        }
        return basePath + (basePath.contains("?") ? "&" : "?") + queryParams;
    }
}
