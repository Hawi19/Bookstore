import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { useSnackbar } from "notistack";
import { Cloudinary } from "@cloudinary/url-gen";
import { auto } from "@cloudinary/url-gen/actions/resize";
import { autoGravity } from "@cloudinary/url-gen/qualifiers/gravity";
import {apiUrl} from '../api/server.js'

const CreateBooks = () => {
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState("");
  const [publishYear, setPublishYear] = useState("");
  const [image, setImage] = useState(null);
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();
  const userId = localStorage.getItem("userId");

  const cld = new Cloudinary({
    cloud: { cloudName: "dcse0t24q" },
  });

  const handleSaveBook = async () => {
    const token = localStorage.getItem("token");

    if (!title || !author || !publishYear) {
      enqueueSnackbar("Please fill in all fields", { variant: "error" });
      return;
    }

    let imageUrl = ""; // To store the uploaded image URL
    if (image) {
      // Upload image to Cloudinary
      const formData = new FormData();
      formData.append("file", image);
      formData.append("upload_preset", "hawigirma");
      formData.append("cloud_name", "dcse0t24q");

      try {
        const uploadRes = await axios.post(
          "https://api.cloudinary.com/v1_1/dcse0t24q/image/upload",
          formData
        );
        imageUrl = uploadRes.data.secure_url; // Get the URL of the uploaded image
        console.log(uploadRes);
      } catch (error) {
        console.error("Error uploading image:", error);
        enqueueSnackbar("Error uploading image. Try again.", {
          variant: "error",
        });
        return;
      }
    }

    // Send book data to the server
    const data = {
      title,
      author,
      publishYear,
      imageUrl, // Include the uploaded image URL
    };

    try {
      await axios.post(`${apiUrl}/books`, data, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });

      enqueueSnackbar("Book created successfully");
      navigate("/home");
    } catch (error) {
      console.log(error);
      enqueueSnackbar("Error occurred. Try again.", { variant: "error" });
    }
  };

  return (
    <div className="p-4">
      <h1 className="my-4">Create Book</h1>
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
        <div className="my-4">
          <label className="text-xl mr-4 text-gray-500">Image</label>
          <input
            type="file"
            onChange={(e) => setImage(e.target.files[0])}
            className="border-2 border-gray-500 px-4 py-2 w-full"
          />
        </div>

        <button className="btn btn-primary btn-lg" onClick={handleSaveBook}>
          Save
        </button>
      </div>
    </div>
  );
};

export default CreateBooks;
