import express from "express";
import { Book } from "../models/bookModel.js";

const router = express.Router();
import { verifyToken } from "../authMiddleware.js";
// Route for Save a new Book
router.post("/", verifyToken, async (request, response) => {
  console.log(request.body);
  console.log("File:", request.file);
  try {
    if (
      !request.body.title ||
      !request.body.author ||
      !request.body.publishYear
    ) {
      return response.status(400).send({
        message: "send all required fields: title, author, publishYear",
      });
    }

    const newBook = {
      title: request.body.title,
      author: request.body.author,
      publishYear: request.body.publishYear,
      imageUrl: request.body.imageUrl,
      userId: request.user.userId,
    };
    const book = await Book.create(newBook);
    return response.status(201).send(book);
  } catch (error) {
    console.log(error.message);
    response.status(500).send({ message: error.message });
  }
});
// Route for Get all books from database
router.get("/", verifyToken, async (request, response) => {
  try {
    const books = await Book.find({ userId: request.user.userId });
    return response.status(200).json({
      count: books.length,
      data: books,
    });
  } catch (error) {
    console.log(error.message);
    response.status(500).send({ message: error.message });
  }
});
// Route books from database by id
router.get("/:id", verifyToken, async (request, response) => {
  try {
    const { id } = request.params;
    const book = await Book.findById(id);
    return response.status(200).json(book);
  } catch (error) {
    console.log(error);
    response.status(500).send({ message: error.message });
  }
});

//Route for update a book
router.put("/:id", verifyToken, async (request, response) => {
  try {
    if (
      !request.body.title ||
      !request.body.author ||
      !request.body.publishYear
    ) {
      return response.status(400).send({
        message: "send all required fields: title, author, publishYear",
      });
    }
    const { id } = request.params;
    const book = await Book.findById(id);
    if (!book) {
      return response.status(404).json({ message: "Book not found" });
    }

    const updatedBook = await Book.findByIdAndUpdate(id, request.body, {
      new: true,
    });

    return response.status(200).send({ message: "Book updated successfully" });
  } catch (error) {
    console.log(error, message);
    response.status(500).send({ message: error.message });
  }
});
//Route for Delete a book
router.delete("/:id", verifyToken, async (request, response) => {
  try {
    const { id } = request.params;
    const book = await Book.findById(id);
    if (!book) {
      return response.status(404).json({ message: "Book not found" });
    }

    await Book.findByIdAndDelete(id);

    return response.status(200).send({ message: "Book deleted successfully" });
  } catch (error) {
    console.log(error.message);
    response.status(500).send({ message: error.message });
  }
});
export default router;
