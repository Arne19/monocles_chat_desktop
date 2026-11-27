import QtQuick
import QtQuick.Effects
import QtQuick.Window

// The quoted photo, sticker or map at the trailing edge of a reply quote: a small square with
// soft corners, like monocles Android's quote card. Cached files only - nothing is fetched.
Item {
    id: root
    property string source: ""   // already a file:/data: URL (window.imageSource)
    property real radius: 6
    readonly property bool ready: img.status === Image.Ready

    // Faint placeholder until the picture is decoded.
    Rectangle {
        anchors.fill: parent
        radius: root.radius
        color: Qt.rgba(1, 1, 1, 0.10)
        visible: !root.ready
    }

    Image {
        id: img
        anchors.fill: parent
        source: root.source
        fillMode: Image.PreserveAspectCrop
        asynchronous: true
        smooth: true
        visible: false
        sourceSize.width: width * Screen.devicePixelRatio
        sourceSize.height: height * Screen.devicePixelRatio
    }
    Item {
        id: roundMask
        anchors.fill: parent
        layer.enabled: true
        layer.smooth: true
        visible: false
        Rectangle { anchors.fill: parent; radius: root.radius; color: "black"; antialiasing: true }
    }
    MultiEffect {
        anchors.fill: parent
        source: img
        maskEnabled: true
        maskSource: roundMask
        // a soft alpha ramp on the mask's antialiased edge instead of a jagged hard cutoff
        maskThresholdMin: 0.5
        maskSpreadAtMin: 1.0
        visible: root.ready
    }
}
