const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);
require("dotenv").config();
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const { GoogleGenAI } = require("@google/genai");

const app = express();
// const PORT = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;


const allowedOrigins = [
  'http://localhost:5173', 
  'http://localhost:5174', 
  'http://localhost:3000', 
  'http://localhost:3001',
  'http://localhost:3002',
   'http://amazonaws.com'
];

const corsOptions = {
  origin: function(origin, callback){
    if(!origin || allowedOrigins.includes(origin)){
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"] 
};

// 2. FIXED: Register CORS precisely ONCE with options tracking rules
app.use(cors(corsOptions));

// 3. Body Parsing Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 4. ADD THIS: A simple health check route to prove your backend handles web requests
app.get("/health-check", (req, res) => {
  res.json({ status: "online", message: "Backend is communicating cleanly!" });
});

// Initialize Gemini Client
const ai = new GoogleGenAI({
  apiKey: process.env.GOOGLE_API_KEY
});

let mongoClient;
let db;

async function connectToMongo() {
  try {
    console.log("Connecting to database cluster...");
    mongoClient = new MongoClient(uri);
    await mongoClient.connect();
    db = mongoClient.db("Users"); 
    console.log("Connected successfully to MongoDB Atlas!");
  } catch (error) {
    console.error("MongoDB connection failed:", error);
    process.exit(1);
  }
}


app.post("/ask-ai", async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Please provide a message" });
    }

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: message,
      // Force structural discipline so the UI always renders elegantly
      config: {
        systemInstruction: `You are a womens health Assist, a premium, supportive reproductive health AI. 
        Keep responses highly structured, bite-sized, and professional. 
        Always use clean markdown headers, bullet points, and brief fragments instead of walls of text. 
        If medical symptoms or remedies are discussed, non-judgmentally mention 3 distinct potential causes or options and advise checking with a professional.`
      }
    });

    res.json({
      reply: response.text
    });

  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "healthy", database: db ? "connected" : "disconnected" });
});



const authenticateBase64 = async (req, res, next) => {
  try {

    console.log("Incoming request headers from terminal:", req.headers);

    const authHeader = req.headers["authorization"] || req.headers["Authorization"];
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return res.status(401).json({ error: "Access Denied: Missing Basic Auth Header" });
    }

    const headerParts = authHeader.split(" ");
    let base64Token = headerParts[1];

    if (!base64Token) {
      return res.status(401).json({ error: "Access Denied: Invalid Basic Format" });
    }

  
    base64Token = base64Token.trim();
    while (base64Token.length % 4 !== 0) {
      base64Token += "=";
    }

    const decodedCredentials = Buffer.from(base64Token, "base64").toString("ascii");
    let [email, password] = decodedCredentials.split(":");

    if (!email || !password) {
      return res.status(401).json({ error: "Authentication failed: Malformed credentials" });
    }

    email = email.trim().toLowerCase();

  
    const user = await db.collection("Users").findOne({
      email: { $regex: new RegExp("^" + email + "$", "i") }
    });

    if (!user) {
      return res.status(401).json({ error: "Authentication failed: User not found" });
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Authentication failed: Wrong password" });
    }

  
    req.user = { id: user._id, email: user.email };
    next();
  } catch (error) {
    res.status(500).json({ error: "Authentication processing error." });
  }
};




app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await db.collection("Users").findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered." });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = {
      name,
      email: normalizedEmail,
      passwordHash,
      role: role || "user",
      createdAt: new Date(),
    };
    const result = await db.collection("Users").insertOne(newUser);

    if (role === "doctor") {
      await db.collection("Doctors").insertOne({
        userId: result.insertedId,
        doctorName: name,
        specialization: "Gynecologist",
        bio: "", location: "", availability: [], rating: 0, reviewsCount: 0,
        createdAt: new Date(),
      });
    }

    res.status(201).json({ message: "Account created successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/signin", async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    email = email.trim().toLowerCase();

    // Find the user in the database
    const user = await db.collection("Users").findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password match." });
    }

    // Verify the hashed password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid username or password match." });
    }

    // Generate a basic token for your frontend Basic Auth system
    const credentials = `${email}:${password}`;
    const token = Buffer.from(credentials).toString("base64");

    // Send successful data and token back to frontend
    res.status(200).json({
      message: "Login successful.",
      token: token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/doctors", async (req, res) => {
  try {
    const doctors = await db.collection("Doctors").find().toArray();
    res.status(200).json(doctors);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/doctors/:id", async (req, res) => {
  try {
    const doctor = await db.collection("Doctors").findOne({ _id: new ObjectId(req.params.id.trim()) });
    if (!doctor) return res.status(404).json({ error: "Doctor not found." });
    res.status(200).json(doctor);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});





app.post("/api/tracker/log", authenticateBase64, async (req, res) => {
  try {
    const { startDate, symptoms, mood } = req.body;
    const newLog = {
      userId: new ObjectId(req.user.id),
      startDate: startDate ? new Date(startDate) : new Date(),
      symptoms: symptoms ? (Array.isArray(symptoms) ? symptoms : [symptoms]) : [],
      mood: mood || "Neutral",
      createdAt: new Date()
    };
    await db.collection("PMS/Period tracker").insertOne(newLog);
    res.status(201).json({ message: "Period health metrics logged successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/tracker/logs", authenticateBase64, async (req, res) => {
  try {
    if (!db) {
      console.error("Database connection missing during logs request.");
      return res.status(200).json([]); 
    }

    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: "Invalid user authentication block." });
    }

    
    const logs = await db.collection("PMS/Period tracker")
      .find({ userId: new ObjectId(req.user.id) }) 
      .sort({ startDate: -1 })
      .toArray();

    res.status(200).json(logs);

  } catch (error) {
    console.error("CRITICAL BACKEND LOGS FAILURE:", error);
    res.status(200).json([]); 
  }
});




app.put("/api/tracker/log/:id", authenticateBase64, async (req, res) => {
  try {
    const { id } = req.params;
    const { endDate, symptoms, mood } = req.body;

    await db.collection("PMS/Period tracker").updateOne(
      {
        _id: new ObjectId(id.trim()),
        userId: new ObjectId(req.user.id)
      },
      {
        $set: {
          endDate: endDate ? new Date(endDate) : null,
          symptoms: symptoms ? (Array.isArray(symptoms) ? symptoms : [symptoms]) : [],
          mood: mood || "Neutral"
        }
      }
    );
    res.status(200).json({ message: "Log entry updated." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.delete("/api/tracker/log/:id", authenticateBase64, async (req, res) => {
  try {
    const { id } = req.params;

    await db.collection("PMS/Period tracker").deleteOne({
      _id: new ObjectId(id.trim()),
      userId: new ObjectId(req.user.id)
    });
    res.status(200).json({ message: "Log entry deleted." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cycle/:userId', async (req, res) => {
  try {
    let cycle = await Cycle.findOne({ userId: req.params.userId });
    if (!cycle) {
      // Safe, default placeholders if they are a completely new user
      return res.json({ lastPeriodDate: "2026-10-16", cycleLength: 28, periodDuration: 5 });
    }
    res.json(cycle);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save or Update Cycle Data Route
app.post('/api/cycle/save', async (req, res) => {
  const { userId, lastPeriodDate, cycleLength, periodDuration } = req.body;
  try {
    let cycle = await Cycle.findOneAndUpdate(
      { userId },
      { lastPeriodDate, cycleLength, periodDuration, updatedAt: Date.now() },
      { new: true, upsert: true } // Upsert: Creates a new document if none exists
    );
    res.json({ success: true, data: cycle });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/bookings/new", authenticateBase64, async (req, res) => {
  try {
    const { doctorId, appointmentDate, reason } = req.body;
    
    // Safety check for inputs
    if (!doctorId) {
      return res.status(400).json({ error: "Missing required parameter: doctorId" });
    }

    const booking = {
      userId: req.user.id, 
      
      appointmentDate: appointmentDate ? new Date(appointmentDate) : new Date(),
      reason: reason || "General Consultation",
      status: "upcoming",
      createdAt: new Date(),
    };

    await db.collection("bookings").insertOne(booking);
    res.status(201).json({ message: "Appointment booked successfully!" });

  } catch (error) {
    console.error("CRITICAL BOOKING CREATION CRASH:", error);
    res.status(500).json({ error: error.message });
  }
});



app.get("/api/bookings/my-list", authenticateBase64, async (req, res) => {
  try {
    const bookings = await db.collection("bookings")
      .find({ userId: new ObjectId(req.user.id) }).sort({ appointmentDate: 1 }).toArray();
    res.status(200).json(bookings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.delete("/api/bookings/:id", authenticateBase64, async (req, res) => {
  try {
    await db.collection("bookings").updateOne(
      { _id: new ObjectId(req.params.id.trim()), userId: new ObjectId(req.user.id) },
      { $set: { status: "cancelled" } }
    );
    res.status(200).json({ message: "Appointment cancelled." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/bookings/dashboard", authenticateBase64, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.id);
    const upcoming = await db.collection("bookings").find({ userId, status: "upcoming" }).toArray();
    const completed = await db.collection("bookings").find({ userId, status: "completed" }).toArray();
    const cancelled = await db.collection("bookings").find({ userId, status: "cancelled" }).toArray();
    res.status(200).json({ upcoming, completed, cancelled });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// stopped

app.post("/api/doctors/review", authenticateBase64, async (req, res) => {
  try {
    const { doctorId, rating, comment } = req.body;
    const review = {
      userId: new ObjectId(req.user.id),
      doctorId: new ObjectId(doctorId.trim()),
      rating: Number(rating) || 5, comment: comment || "", createdAt: new Date(),
    };


    await db.collection("ReviewsDoctors").insertOne(review);
    res.status(201).json({ message: "Doctor review submitted." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/doctors/:id/reviews", authenticateBase64, async (req, res) => {
  try {
    const reviews = await db.collection("ReviewsDoctors")
      .find({ doctorId: new ObjectId(req.params.id.trim()) })
      .sort({ createdAt: -1 })
      .toArray();
    res.status(200).json(reviews);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



app.post("/api/products", authenticateBase64, async (req, res) => {
  try {
    const { name, category, description, priceNote, externalLink, image } = req.body;
    const product = { name, category, description, priceNote, externalLink, image, createdAt: new Date() };
    await db.collection("Products").insertOne(product);
    res.status(201).json({ message: "Product added successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/products", async (req, res) => {
  try {
    const products = await db.collection("Products").find().toArray();
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await db.collection("Products").findOne({ _id: new ObjectId(req.params.id.trim()) });
    if (!product) return res.status(404).json({ error: "Product not found." });
    res.status(200).json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});




app.put("/api/wishlist/notes", authenticateBase64, async (req, res) => {
  try {
    const { productId, userNotes } = req.body;
    if (!productId) return res.status(400).json({ error: "Missing productId parameter." });

    await db.collection("wishlist").updateOne(
      { userId: new ObjectId(req.user.id) },
      { $set: { [`notes.${productId.trim()}`]: userNotes || "" } }
    );

    res.status(200).json({ message: "Wishlist shopping notes updated successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/api/products/:id/reviews", authenticateBase64, async (req, res) => {
  try {
    const reviews = await db.collection("ReviewsProducts")
      .find({ productId: new ObjectId(req.params.id.trim()) })
      .sort({ createdAt: -1 })
      .toArray();
    res.status(200).json(reviews);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});




app.delete("/api/products/review/:id", authenticateBase64, async (req, res) => {
  try {
    await db.collection("ReviewsProducts").deleteOne({
      _id: new ObjectId(req.params.id.trim()),
      userId: new ObjectId(req.user.id)
    });

    res.status(200).json({ message: "Review deleted." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/wishlist/add", authenticateBase64, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId) return res.status(400).json({ error: "Missing productId." });
    await db.collection("wishlist").updateOne(
      { userId: new ObjectId(req.user.id) },
      { $addToSet: { productIds: productId.trim() } }, 
      { upsert: true }
    );

    res.status(201).json({ message: "Product successfully bookmarked to your wishlist." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



app.get("/api/wishlist", authenticateBase64, async (req, res) => {
  try {
    const userWishlist = await db.collection("wishlist").findOne({ userId: new ObjectId(req.user.id) });
    if (!userWishlist) return res.status(200).json([]);

    
    res.status(200).json(userWishlist.productIds || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/wishlist/remove", authenticateBase64, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId) return res.status(400).json({ error: "Missing productId parameter." });
    const result = await db.collection("wishlist").updateOne(
      { userId: new ObjectId(req.user.id) },
      { $pull: { productIds: productId.trim() } } 
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "Product was not found in your wishlist." });
    }

    res.status(200).json({ message: "Product successfully removed from your wishlist." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



app.put("/api/wishlist/notes", authenticateBase64, async (req, res) => {
  try {
    const { productId, userNotes } = req.body;
    if (!productId) return res.status(400).json({ error: "Missing productId parameter." });

    await db.collection("wishlist").updateOne(
      { userId: new ObjectId(req.user.id) },
      { $set: { [`notes.${productId.trim()}`]: userNotes || "" } }
    );

    res.status(200).json({ message: "Wishlist shopping notes updated successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// TEMPORARY: Developer route to mass-insert doctor records
app.post("/api/admin/seed-doctors", async (req, res) => {
  try {
    const doctorsList = req.body;
    if (!Array.isArray(doctorsList) || doctorsList.length === 0) {
      return res.status(400).json({ error: "Please provide an array of doctors." });
    }

    await db.collection("doctors").deleteMany({});

    const result = await db.collection("doctors").insertMany(doctorsList);
    res.status(201).json({ message: "Successfully seeded doctors collection!", count: result.insertedCount });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


connectToMongo().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running successfully on port ${PORT}`);
  });
});
