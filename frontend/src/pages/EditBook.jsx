import React from "react";
import { useState, useEffect } from "react";
import BackButton from "../components/BackButton";
import axios from "axios";
import { useNavigate, useParams } from "react-router-dom";
import { apiUrl } from "../api/server";

const EditBook = () => {
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState("");
  const [publishYear, setPublishYear] = useState("");
  const navigate = useNavigate();
  const { id } = useParams();
  useEffect(() => {
    const token = localStorage.getItem("token");
      if (!token) {
        alert("No token found.");
        navigate("/login"); 
        return;
      }
    axios
      .get(`${apiUrl}/books/${id}`, {
        headers: {
          Authorization: `Bearer ${token}`, // Add token in the Authorization header
        },
      })
      .then((response) => {
        setAuthor(response.data.author);
        setPublishYear(response.data.publishYear);
        setTitle(response.data.title);
      })
      .catch((error) => {
        alert("An error happened. Please Check console");
        console.log(error);
      });
  }, [id, navigate]);
  const handleEditBook = () => {
    const token = localStorage.getItem("token");
      if (!token) {
        alert("No token found. Please log in.");
        navigate("/login");
        return;
      }
    const data = {
      title,
      author,
      publishYear,
    };
    axios
      .put(`${apiUrl}/books/${id}`, data, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })
      .then((res) => {
        alert("Book updated successfully!");
        navigate("/home");
      })
      .catch((error) => {
        alert("Please check the console.");
        console.log(error);
      });
  };
  return (
    <div className="p-4">
      <BackButton />
      <h1 className="my-4">Edit Book</h1>
      <div className="p-4">
        <div className="my-4">
          <label className="mx-4">Title</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="mx-5 px-4 py-2"
          />
        </div>
        <div className="my-4">
          <label className="mx-4">Author</label>
          <input
            type="text"
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            className="mx-4 px-4 py-2"
          />
        </div>

        <div className="my-4">
          <label className="mx-2">Publish Year</label>
          <input
            type="number"
            value={publishYear}
            onChange={(e) => setPublishYear(e.target.value)}
            className=" mx-4 px-4 py-2"
          />
        </div>

        <button className="btn btn-primary btn-lg" onClick={handleEditBook}>
          Save
        </button>
      </div>
    </div>
  );
};

export default EditBook;
