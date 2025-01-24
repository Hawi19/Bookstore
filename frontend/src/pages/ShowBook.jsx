import React from "react";
import { useEffect, useState } from "react";
import axios from "axios";
import { useParams } from "react-router-dom";
import BackButton from "../components/BackButton";
import { apiUrl } from "../api/server";

const ShowBook = () => {
  const [book, setBook] = useState({});
  const { id } = useParams();
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      console.log("No token found");
      navigate("/");
      return;
    }
    axios
      .get(`${apiUrl}/books/${id}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })
      .then((response) => {
        setBook(response.data);
        console.log(response.data);
      })
      .catch((error) => {
        console.log(error);
      });
  }, []);
  return (
    <div className="p-4">
      <BackButton />
      <h1 className="my-4">Show Book</h1>
      <div className="border border-2 rounded rounded-xl p-4">
        {book.imageUrl && (
          <div className="w-1/3 pr-4">
            <img src={book.imageUrl} alt={book.title} />
          </div>
        )}
        <div className="my-4">
          <span className="border p-1 rounded mx-2">Id</span>
          <span>{book._id}</span>
        </div>
        <div className="my-4">
          <span className="border p-1 rounded mx-2">Title</span>
          <span>{book.title}</span>
        </div>
        <div className="my-4">
          <span className="border p-1 rounded mx-2">Author</span>
          <span>{book.author}</span>
        </div>
        <div className="my-4">
          <span className="border p-1 rounded mx-2">Publish Year</span>
          <span>{book.publishYear}</span>
        </div>
        <div className="my-4">
          <span className="border p-1 rounded mx-2">Create Time</span>
          <span>{new Date(book.createdAt).toString()}</span>
        </div>
        <div className="my-4">
          <span className="border p-1 rounded mx-2">Last Update Time</span>
          <span>{new Date(book.updatedAt).toString()}</span>
        </div>
      </div>
    </div>
  );
};

export default ShowBook;
