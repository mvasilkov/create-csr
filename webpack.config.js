module.exports = {
    entry: './app.js',
    output: {
        filename: 'app.build.js',
        path: __dirname,
    },
    mode: 'development',
    module: {
        rules: [
            {
                test: /\.js$/,
                use: {
                    loader: 'babel-loader',
                },
            },
        ],
    },
}
