using System;

namespace ShazrinSonar.Processing
{
    public static class GeofenceManager
    {
        // Thread-safe storage for the vessel's last known live location
        // These are updated continuously by the Record 1003 parser
        private static double _currentLatitude = 0.0;
        private static double _currentLongitude = 0.0;
        private static readonly object _lock = new object();

        // Polygon vertices converted from DMS to Decimal Degrees
        // Supports any number of points (3+) for complex, irregular survey areas
        private static readonly (double Lat, double Lon)[] Polygon = new[]
        {
            (2.928072, 101.335228), // A. 2°55'41.06"N 101°20'06.82"E
            (2.920997, 101.339667), // B. 2°55'15.59"N 101°20'22.80"E
            (2.923997, 101.342856), // C. 2°55'26.39"N 101°20'34.28"E
            (2.929503, 101.339189)  // D. 2°55'46.21"N 101°20'21.08"E
        };

        /// <summary>
        /// Updates the vessel's live position in memory. 
        /// Called automatically every time a new Record 1003 arrives.
        /// </summary>
        public static void UpdatePosition(double latitude, double longitude)
        {
            lock (_lock)
            {
                _currentLatitude = latitude;
                _currentLongitude = longitude;
            }
        }

        /// <summary>
        /// Evaluates if the last known GPS position is inside the defined polygon.
        /// Called by the Record 7027 processor for every ping.
        /// </summary>
        public static bool IsInsideTargetZone()
        {
            double currentLat;
            double currentLon;

            lock (_lock)
            {
                currentLat = _currentLatitude;
                currentLon = _currentLongitude;
            }

            // Failsafe: If no GPS data has been received yet, disable modifications
            if (currentLat == 0.0 && currentLon == 0.0) return false;

            // Ray-Casting Algorithm: Determines if a point is inside a polygon
            // by drawing a horizontal line and counting edge intersections.
            bool isInside = false;
            int j = Polygon.Length - 1; // Start with the last vertex to close the loop

            for (int i = 0; i < Polygon.Length; i++)
            {
                // Check if the current point's Longitude falls between the Longitudes of the edge (i, j)
                if ((Polygon[i].Lon < currentLon && Polygon[j].Lon >= currentLon) ||
                    (Polygon[j].Lon < currentLon && Polygon[i].Lon >= currentLon))
                {
                    // Calculate the Latitude of the intersection point on the edge.
                    // If the vessel's Latitude is below this intersection, the ray crosses the edge.
                    if (Polygon[i].Lat + (currentLon - Polygon[i].Lon) /
                        (Polygon[j].Lon - Polygon[i].Lon) *
                        (Polygon[j].Lat - Polygon[i].Lat) < currentLat)
                    {
                        isInside = !isInside; // Toggle state (Odd = Inside, Even = Outside)
                    }
                }
                j = i;
            }

            return isInside;
        }

        /// <summary>
        /// Retrieves the current live coordinates for diagnostic logging.
        /// </summary>
        public static (double Lat, double Lon) GetCurrentPosition()
        {
            lock (_lock)
            {
                return (_currentLatitude, _currentLongitude);
            }
        }
    }
}