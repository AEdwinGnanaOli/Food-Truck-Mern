import React, { useEffect, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import AOS from "aos";
import "aos/dist/aos.css";
import { makeRequest } from "../../services/apiServices";
import { useSelector } from "react-redux";
import ProductCard from "../../components/cards/ProductCard";
import { toast } from "react-hot-toast"; // Optional for user feedback

function Home({ colors }) {
  const { userInfo, isLoggedIn } = useSelector((state) => state.user);
  const userId = userInfo?.user?.id;
  const queryClient = useQueryClient();

  const {
    data: items = [],
    isLoading,
    isError,
    error
  } = useQuery({
    queryKey: ["products"],
    queryFn: () => makeRequest("/product/all", "GET"),
    staleTime: 5 * 60 * 1000,
    cacheTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
    select: (data) => data.data
  });

  const { mutate } = useMutation({
    mutationFn: (id) => makeRequest(`/product/like/${id}`, "PUT", { userId }),
    onMutate: async (id) => {
      await queryClient.cancelQueries(["products"]);
      const previousProducts = queryClient.getQueryData(["products"]);
      queryClient.setQueryData(["products"], (old) => {
        if (!Array.isArray(old)) return old;
        return old.map((item) =>
          item._id === id
            ? {
                ...item,
                usersLiked: item.usersLiked.includes(userId)
                  ? item.usersLiked.filter((user) => user !== userId)
                  : [...item.usersLiked, userId],
                likes: item.usersLiked.includes(userId)
                  ? item.likes - 1
                  : item.likes + 1
              }
            : item
        );
      });
      return { previousProducts };
    },
    onError: (error, id, context) => {
      toast.error("Failed to like the product.");
      queryClient.setQueryData(["products"], context.previousProducts);
    },
    onSettled: () => {
      queryClient.invalidateQueries(["products"]);
    }
  });
  useEffect(() => {
    AOS.init();
  }, []);
  const handleLike = (id) => {

    mutate(id, {
      onError: (err) => console.error("Mutation failed:", err),
      onSuccess: (data) => toast.success("Product liked successfully")
    });
  };
  const renderedItems = useMemo(
    () =>
      items.map((product) => (
        <ProductCard
          key={product._id}
          product={product}
          userId={userId}
          onLike={handleLike}
        />
      )),
    [items, userId, mutate]
  );
  // const renderedProfile = useMemo(() => {
  //   if (!item) return null;
  //   const dataArray = Array.isArray(item) ? item : [item];
  //   return dataArray.map((data) => (
  //     <Profile
  //       open={isOpen}
  //       close={closeDialog}
  //       update={"none"}
  //       deleted={"none"}
  //       id={data._id}
  //       name={data.name}
  //       phone={data.phone}
  //       email={data.email}
  //     />
  //   ));
  // }, [item, openDialog, isOpen]);

  if (isLoading) return <div>Loading...</div>;
  if (isError) return <div>Error: {error.message}</div>;

  return (
    <div className="container mx-auto px-4 py-8 overflow-hidden relative">
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-6">
        {renderedItems}
      </div>
    </div>
  );
}

export default Home;
