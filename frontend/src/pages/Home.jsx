import React from "react";
import "bootstrap/dist/css/bootstrap.css";
import { useState, useEffect } from "react";
import axios from "axios";
import { Link, useNavigate } from "react-router-dom";
import { MdOutlineAddBox } from "react-icons/md";
import BooksTable from "../components/home/BooksTable";
import { apiUrl } from "../api/server";

const Home = () => {
  const [books, setBooks] = useState([]);
  const navigate = useNavigate();
  const usernameLocal = localStorage.getItem("user");
  const token = localStorage.getItem("token");

  if (!token) {
    navigate("/");
  }
  const handleLogOut = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigate("/");
  };

  useEffect(() => {
    axios
      .get(`${apiUrl}/books`, {
        headers: {
          Authorization: `Bearer ${token}`, // Send the token
        },
      })
      .then((response) => {
        setBooks(response.data.data);
        console.log("data", response.data.data);
      })
      .catch((error) => {
        console.log(error);
      });
  }, [token]);
  return (
    <div className="container p-4">
      <div className="flex justify-between items-center">
        <h1 className="lead display-4 mt-5">Books List</h1>
        <Link to="/books/create">
          <MdOutlineAddBox className="display-5" />
        </Link>
        <span className="mx-2">Welcome, {usernameLocal}!</span>
        <button className="brn btn-primary my-3" onClick={handleLogOut}>
          Log Out
        </button>
      </div>
      <BooksTable books={books} />
    </div>
  );
};

export default Home;
