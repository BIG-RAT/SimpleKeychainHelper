// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JPCredentials",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(
            name: "JPCredentials", targets: ["JPCredentials"])
    ],
    targets: [
        .target(name: "JPCredentials", dependencies: [], path: "Sources/JPCredentials"),
        .testTarget(name: "JPCredentialsTests", dependencies: ["JPCredentials"], path: "Tests/JPCredentialsTests")
    ]
)
