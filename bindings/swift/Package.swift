// swift-tools-version:5.9
import PackageDescription

let package = Package(
  name: "AntechKdf",
  platforms: [
    .macOS(.v12),
    .iOS(.v15),
  ],
  products: [
    .library(name: "AntechKdf", targets: ["AntechKdf"]),
  ],
  targets: [
    .systemLibrary(name: "CAntechKdf", path: "Sources/CAntechKdf"),
    .target(
      name: "AntechKdf",
      dependencies: ["CAntechKdf"],
      path: "Sources/AntechKdf"
    ),
  ]
)
