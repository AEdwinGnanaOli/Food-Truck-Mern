import { useQuery } from "@tanstack/react-query";
import React, { useMemo } from "react";
import { makeRequest } from "../../services/apiServices";
import { toast } from "react-hot-toast";
import { Card, Typography } from "@material-tailwind/react";
import useDialog from "../../hooks/useDialog";
import Delete from "../../components/Delete";
import RestoreFromTrashIcon from "@mui/icons-material/RestoreFromTrash";
import CreateIcon from "@mui/icons-material/Create";
import { useNavigate } from "react-router-dom";
import useProductQuery from "../../hooks/products/useProductQuery";
import ProductTableCard from "../../components/cards/ProductTableCard";
import useProductCrud from "../../hooks/products/useProductCrud";

export default function Products() {
  const navigate = useNavigate();
  const TABLE_HEAD = [
    "ShopImage",
    "MenuImage",
    "ProductName",
    "Phone",
    "Address",
    "Description",
    "Price",
    "StartTime",
    "EndTime",
    "Action"
  ];
  const { isOpen, openDialog, closeDialog } = useDialog();

  const { data: products = [], isLoading, isError, error } = useProductQuery();

  const renderedTableRows = useMemo(() => {
    if (products.length === 0) {
      return (
        <tr>
          <td colSpan={10} className="text-center p-4">
            No users available.
          </td>
        </tr>
      );
    }
    return products.map((product) => {
      const {
        _id,
        shopImage,
        menuImage,
        shopName,
        phone,
        address,
        description,
        price,
        startTime,
        endTime
      } = product;

      return (
        <>
          <ProductTableCard
            id={_id}
            shopImage={shopImage}
            menuImage={menuImage}
            shopName={shopName}
            phone={phone}
            address={address}
            description={description}
            price={price}
            startTime={startTime}
            endTime={endTime}
            // event={deleteProduct}
            openDialog={openDialog}
            isOpen={isOpen}
            closeDialog={closeDialog}
          />
        </>
      );
    });
  }, [products, navigate, openDialog, closeDialog, isOpen]);
  if (isLoading) {
    return <div className="text-center mt-10">Loading...</div>;
  }
  if (isError) {
    return <div className="text-center mt-10">Failed to load users.</div>;
  }
  return (
    <div className="p-4">
      <div className="flex justify-end mb-4">
        <button
          className="bg-green-700 text-white px-4 py-2 rounded hover:bg-green-800 transition duration-200"
          onClick={() => navigate("/vendor/products/sign-up")}
        >
          Add Product <span className="text-xl">+</span>
        </button>
      </div>
      <Card className="overflow-auto border-2 rounded-lg">
        <table className="w-full min-w-max table-auto text-left">
          <thead>
            <tr>
              {TABLE_HEAD.map((head) => (
                <th
                  key={head}
                  className="border-b border-blue-gray-100 bg-blue-gray-50 p-4"
                >
                  <Typography
                    variant="small"
                    color="blue-gray"
                    className="font-normal leading-none opacity-70"
                  >
                    {head}
                  </Typography>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>{renderedTableRows}</tbody>
        </table>
      </Card>
    </div>
  );
}