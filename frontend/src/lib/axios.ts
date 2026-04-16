import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:5000', // BE
  withCredentials: true, // for cookie
});