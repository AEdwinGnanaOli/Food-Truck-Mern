import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { makeRequest } from "../../services/apiServices";
import { toast } from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";


function useProductCrud() {
  const { user, isLoggedIn } = useSelector((state) => state.user);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Fetch single product or all products for a vendor
  const useFetchProducts = ({vendorId = null, productId = null }) => {
    const endpoint = productId
      ? `/product/one/${productId}`
      : vendorId
      ? `/product/vendor/${vendorId}`
      : "/product";

    return useQuery({
      queryKey: ["products", vendorId, productId].filter(Boolean),
      queryFn: () => makeRequest(endpoint, "GET"),
      staleTime: 5 * 60 * 1000,
      cacheTime: 10 * 60 * 1000,
      refetchOnWindowFocus: false,
      select: (data) => (productId ? data : data?.products || []),
      enabled: Boolean(vendorId || productId)
    });
  };

  // Update product
  const updateMutation = useMutation({
    mutationFn: ({ productId, updateData }) =>
      makeRequest(`/product/update/${productId}`, "PUT", updateData),
    onMutate: async ({ productId, updateData }) => {
      await queryClient.cancelQueries(["products", productId]);
      const previousData = queryClient.getQueryData(["products", productId]);

      queryClient.setQueryData(["products", productId], (oldData) =>
        oldData ? { ...oldData, ...updateData } : oldData
      );

      return { previousData };
    },
    onError: (_, __, context) => {
      if (context?.previousData) {
        queryClient.setQueryData(
          ["products", context.previousData.productId],
          context.previousData
        );
      }
      toast.error("Update failed. Please try again.");
    },
    onSuccess: () => {
      toast.success("Product updated successfully.");
      const redirectPath = isLoggedIn
        ? user?.role === "admin"
          ? "/admin"
          : "/user"
        : "/login";
      navigate(redirectPath);
    },
    onSettled: ({ productId }) => {
      queryClient.invalidateQueries(["product", productId]);
    }
  });


  return {
    useFetchProducts,
    updateProduct: updateMutation.mutate,
  };
}

export default useProductCrud;
