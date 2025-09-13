import { Request, Response } from 'express';
import User from '../models/User';
import { v4 as uuidv4 } from 'uuid';

export class UserController {
  // Register a new user
  static async register(req: Request, res: Response) {
    try {
      const { email, password, name } = req.body;

      // Validation
      if (!email || !password || !name) {
        return res.status(400).json({ 
          error: 'invalid_request', 
          error_description: 'Email, password, and name are required' 
        });
      }

      if (password.length < 6) {
        return res.status(400).json({ 
          error: 'invalid_request', 
          error_description: 'Password must be at least 6 characters long' 
        });
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ 
          error: 'user_exists', 
          error_description: 'User with this email already exists' 
        });
      }

      // Create new user
      const user = new User({
        email,
        password,
        name,
        isVerified: false // You can implement email verification later
      });

      await user.save();

      // Return user info (without password)
      return res.status(201).json({
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        message: 'User registered successfully. Please verify your email.'
      });

    } catch (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ 
        error: 'server_error', 
        error_description: 'Internal server error' 
      });
    }
  }

  // Get user profile
  static async getProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user.sub;
      const user = await User.findById(userId).select('-password');
      
      if (!user) {
        return res.status(404).json({ 
          error: 'user_not_found', 
          error_description: 'User not found' 
        });
      }

      return res.json({
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        createdAt: user.createdAt
      });

    } catch (error) {
      console.error('Get profile error:', error);
      return res.status(500).json({ 
        error: 'server_error', 
        error_description: 'Internal server error' 
      });
    }
  }

  // Update user profile
  static async updateProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user.sub;
      const { name } = req.body;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ 
          error: 'user_not_found', 
          error_description: 'User not found' 
        });
      }

      if (name) user.name = name;
      await user.save();

      return res.json({
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        message: 'Profile updated successfully'
      });

    } catch (error) {
      console.error('Update profile error:', error);
      return res.status(500).json({ 
        error: 'server_error', 
        error_description: 'Internal server error' 
      });
    }
  }
}