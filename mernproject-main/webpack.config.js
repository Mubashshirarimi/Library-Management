const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  entry: './src/index.js',  // Your entry point file (React app starts here)
  output: {
    filename: 'bundle.js',  // The compiled bundle filename
    path: path.resolve(__dirname, 'dist'),  // Output directory
    clean: true,  // Clean dist folder before each build
  },
  mode: 'development',  // Set to 'production' for production build
  devtool: 'source-map',  // For better debugging (shows original source)
  devServer: {
    static: './dist',  // Serve static files from the 'dist' directory
    hot: true,  // Enable hot module replacement for faster development
  },
  module: {
    rules: [
      {
        test: /\.jsx?$/,  // Match all .js and .jsx files
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',  // Use Babel to transpile JS/JSX
          options: {
            presets: ['@babel/preset-env', '@babel/preset-react'],  // For ES6+ and React JSX
          },
        },
      },
      {
        test: /\.css$/,  // Match .css files
        use: [
          'style-loader',  // Injects CSS into the DOM
          'css-loader',    // Resolves CSS imports into JS
          'postcss-loader', // For Tailwind CSS processing
        ],
      },
    ],
  },
  resolve: {
    extensions: ['.js', '.jsx'],  // Allow importing without file extensions
    fallback: {
      "path": require.resolve("path-browserify"),  // Polyfill for 'path' module
      "crypto": require.resolve("crypto-browserify"), // Polyfill for 'crypto' module
      "querystring": require.resolve("querystring-es3"), // Polyfill for 'querystring' module
      "url": require.resolve("url/"), // Polyfill for 'url' module
      "buffer": require.resolve("buffer/"), // Polyfill for 'buffer' module
      "stream": require.resolve("stream-browserify"), // Polyfill for 'stream' module
      "util": require.resolve("util/"), // Polyfill for 'util' module
      "zlib": require.resolve("zlib-browserify") // Polyfill for 'zlib' module
    }
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './public/index.html',  // Your HTML template file
    }),
  ],
};
