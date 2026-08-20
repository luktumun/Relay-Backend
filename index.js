import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import crypto from 'node:crypto'
import nodemailer from 'nodemailer'

const app = express()
const port = process.env.PORT || 5000
const jwtSecret = process.env.JWT_SECRET || 'replace-this-secret-in-production'
app.use(cors())
app.use(express.json())

const userSchema = new mongoose.Schema({ name: { type: String, required: true }, email: { type: String, required: true, unique: true, lowercase: true }, passwordHash: { type: String, required: true } }, { timestamps: true })
const projectSchema = new mongoose.Schema({ name: String, description: String, category: String, price: Number, available: Boolean, image: String }, { timestamps: true })
const orderSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, required: true }, projectId: { type: mongoose.Schema.Types.ObjectId, required: true }, trackingNumber: { type: String, unique: true }, status: String }, { timestamps: true })
const resetTokenSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, required: true }, tokenHash: { type: String, unique: true }, expiresAt: { type: Date, expires: 0 } })
const User = mongoose.model('User', userSchema)
const Project = mongoose.model('Project', projectSchema)
const Order = mongoose.model('Order', orderSchema)
const ResetToken = mongoose.model('ResetToken', resetTokenSchema)

function tokenFor(user) { return jwt.sign({ id: user._id.toString() }, jwtSecret, { expiresIn: '7d' }) }
function publicUser(user) { return { id: user._id.toString(), name: user.name, email: user.email } }
function mailer() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASSWORD) return null
  return nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } })
}
function auth(req, res, next) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ message: 'Please sign in to continue.' })
  try { req.userId = jwt.verify(header.slice(7), jwtSecret).id; next() } catch { return res.status(401).json({ message: 'Your session has expired. Please sign in again.' }) }
}
function liveStatus(order) {
  const ageSeconds = (Date.now() - new Date(order.createdAt).getTime()) / 1000
  if (ageSeconds >= 60) return { status: 'Delivered', progress: 100 }
  if (ageSeconds >= 15) return { status: 'In transit', progress: 60 + Math.min(39, Math.floor((ageSeconds - 15) / 1.2)) }
  return { status: 'Order confirmed', progress: 25 + Math.floor(ageSeconds) }
}
async function orderResponse(order) {
  const project = await Project.findById(order.projectId).lean()
  return { _id: order._id, project, trackingNumber: order.trackingNumber, createdAt: order.createdAt, ...liveStatus(order) }
}

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ message: 'Name, email, and a password of at least 6 characters are required.' })
  if (await User.findOne({ email })) return res.status(409).json({ message: 'An account with this email already exists.' })
  const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12) })
  res.status(201).json({ token: tokenFor(user), user: publicUser(user) })
})
app.post('/api/auth/signin', async (req, res) => {
  const user = await User.findOne({ email: req.body.email })
  if (!user || !(await bcrypt.compare(req.body.password || '', user.passwordHash))) return res.status(401).json({ message: 'Invalid email or password.' })
  res.json({ token: tokenFor(user), user: publicUser(user) })
})
app.post('/api/auth/forgot-password', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase()
  const user = await User.findOne({ email })
  if (user) {
    const rawToken = crypto.randomBytes(32).toString('hex')
    await ResetToken.deleteMany({ userId: user._id })
    await ResetToken.create({ userId: user._id, tokenHash: crypto.createHash('sha256').update(rawToken).digest('hex'), expiresAt: new Date(Date.now() + 15 * 60 * 1000) })
    const resetUrl = `${process.env.CLIENT_URL || 'http://localhost:5173'}?resetToken=${rawToken}`
    const transport = mailer()
    if (transport) await transport.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to: user.email, subject: 'Reset your Relay password', text: `Reset your password using this link: ${resetUrl}` })
    else console.log(`Password reset link for ${user.email}: ${resetUrl}`)
  }
  res.json({ message: 'If an account exists for that email, a reset link has been sent.' })
})
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body
  if (!token || !password || password.length < 6) return res.status(400).json({ message: 'A valid reset token and password of at least 6 characters are required.' })
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  const reset = await ResetToken.findOne({ tokenHash, expiresAt: { $gt: new Date() } })
  if (!reset) return res.status(400).json({ message: 'This reset link is invalid or expired.' })
  await User.findByIdAndUpdate(reset.userId, { passwordHash: await bcrypt.hash(password, 12) })
  await ResetToken.deleteOne({ _id: reset._id })
  res.json({ message: 'Password updated. You can now sign in.' })
})
app.get('/api/projects', auth, async (_req, res) => res.json(await Project.find({ available: true }).sort({ createdAt: -1 }).lean()))
app.get('/api/orders', auth, async (req, res) => {
  const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 })
  res.json(await Promise.all(orders.map(orderResponse)))
})
app.post('/api/purchases', auth, async (req, res) => {
  const project = await Project.findOne({ _id: req.body.projectId, available: true })
  if (!project) return res.status(404).json({ message: 'Project is not available.' })
  const existing = await Order.findOne({ userId: req.userId, projectId: project._id })
  if (existing) return res.status(409).json({ message: 'You already own this project.' })
  const order = await Order.create({ userId: req.userId, projectId: project._id, trackingNumber: `RL-${Date.now().toString().slice(-8)}`, status: 'Order confirmed' })
  res.status(201).json(await orderResponse(order))
})
app.get('/api/health', (_req, res) => res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }))

const seedProjects = [
  { name: 'Delivery Tracking Dashboard', description: 'A polished operations dashboard for managing orders and live delivery status.', category: 'Logistics', price: 149, available: true, image: 'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?auto=format&fit=crop&w=900&q=80' },
  { name: 'SaaS Analytics Starter', description: 'Conversion-ready analytics screens with KPI cards, charts, and team views.', category: 'Analytics', price: 99, available: true, image: 'https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=900&q=80' },
  { name: 'Marketplace Admin Portal', description: 'Manage products, customers, orders, and inventory from a clean admin workspace.', category: 'Commerce', price: 129, available: true, image: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=900&q=80' },
  { name: 'Team Collaboration Workspace', description: 'A focused workspace for projects, tasks, comments, and team delivery.', category: 'Productivity', price: 119, available: true, image: 'https://images.unsplash.com/photo-1556761175-b413da4baf72?auto=format&fit=crop&w=900&q=80' },
]

const configuredMongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/relay-projects'
const mongoUri = configuredMongoUri.endsWith('/') ? `${configuredMongoUri}relay-projects` : configuredMongoUri

mongoose.connect(mongoUri).then(async () => {
  if (await Project.countDocuments() === 0) await Project.insertMany(seedProjects)
  app.listen(port, () => console.log(`Relay API running on http://localhost:${port}`))
}).catch((error) => { console.error('MongoDB connection failed:', error.message); process.exit(1) })
