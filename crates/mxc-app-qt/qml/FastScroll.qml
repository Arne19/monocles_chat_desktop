import QtQuick
import QtQuick.Controls

// Fast, direct scrolling for mouse wheels and touchpads: every event moves the view
// immediately — no animation, no inertia — just scaled to cover more distance than Qt's
// slow defaults. Declare inside a vertical Flickable/ListView/GridView; it disables itself
// when there is nothing to scroll.
//
// Since the Flickable never sees these events, its attached scrollbar is shown manually
// while scrolling (the Material auto-hide fade needs `active`).
WheelHandler {
    id: root

    // Touchpad finger-distance multiplier (1.0 = the device's native 1:1 speed).
    property real speedFactor: 4.0
    // Pixels per clicky-wheel notch (Qt's native step is 72).
    property real stepSize: 320

    // A handler declared inside a Flickable is REPARENTED into its contentItem (so `parent`
    // is a plain Item, NOT the Flickable — `parent as Flickable` alone is always null and
    // silently disables the handler). The Flickable is the contentItem's parent.
    readonly property Flickable flick: {
        if (parent instanceof Flickable)
            return parent
        if (parent && parent.parent instanceof Flickable)
            return parent.parent
        return null
    }

    // Emitted after each wheel/touchpad step this handler applied. The Flickable never sees
    // these events, so it doesn't report them as `moving` — a view that must tell user scrolling
    // from layout changes (the chat's stick-to-bottom) listens here.
    signal scrolled()

    target: null
    orientation: Qt.Vertical
    acceptedDevices: PointerDevice.AllDevices
    enabled: flick !== null && flick.contentHeight > flick.height

    // Lets the auto-hiding scrollbar fade back out after the last event.
    readonly property Timer barTimer: Timer {
        interval: 700
        onTriggered: {
            const bar = root.flick ? root.flick.ScrollBar.vertical : null
            if (bar)
                bar.active = false
        }
    }

    onWheel: (event) => {
        const f = flick
        if (!f)
            return
        // Touchpads report pixelDelta; clicky wheels only angleDelta (±120 per notch).
        const dy = event.pixelDelta.y !== 0 ? event.pixelDelta.y * speedFactor
                                            : (event.angleDelta.y / 120) * stepSize
        if (dy === 0)
            return
        const minY = f.originY - f.topMargin
        const maxY = Math.max(minY, f.originY + f.contentHeight + f.bottomMargin - f.height)
        f.contentY = Math.max(minY, Math.min(maxY, f.contentY - dy))
        root.scrolled()
        const bar = f.ScrollBar.vertical
        if (bar) {
            bar.active = true
            barTimer.restart()
        }
    }
}
