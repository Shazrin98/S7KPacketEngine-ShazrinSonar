using System;
using System.Collections.Generic;
using System.Linq;

namespace ShazrinSonar.Processing
{
    public static class GeofenceManager
    {
        // Thread-safe storage for the vessel's last known live location
        private static double _currentLatitude = 0.0;
        private static double _currentLongitude = 0.0;
        private static readonly object _lock = new object();

        // Dynamic polygon backing field
        // Starts empty. Populated via JSON config injection.
        private static (double Lat, double Lon)[] _polygon = Array.Empty<(double, double)>();

        /// <summary>
        /// Updates the polygon vertices dynamically. 
        /// Thread-safe to prevent race conditions with incoming ping processing.
        /// </summary>
        public static void SetPolygon(IEnumerable<(double Lat, double Lon)> vertices)
        {
            lock (_lock)
            {
                _polygon = vertices.ToArray();
            }
        }

        /// <summary>
        /// Updates the vessel's live position in memory. 
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
        /// </summary>
        public static bool IsInsideTargetZone()
        {
            double currentLat;
            double currentLon;
            (double Lat, double Lon)[] poly;

            // Safely copy references before executing math to prevent crashes
            // if the config file is reloaded exactly while a ping is being processed.
            lock (_lock)
            {
                currentLat = _currentLatitude;
                currentLon = _currentLongitude;
                poly = _polygon; 
            }

            // Failsafes: Disable spoofing if no GPS data exists yet
            if (currentLat == 0.0 && currentLon == 0.0) return false;
            
            // Failsafe: A valid polygon mathematically requires at least 3 points
            if (poly.Length < 3) return false; 

            // Ray-Casting Algorithm: Determines if a point is inside a polygon
            // by drawing a horizontal line and counting edge intersections.
            bool isInside = false;
            int j = poly.Length - 1; // Start with the last vertex to close the loop

            for (int i = 0; i < poly.Length; i++)
            {
                // Check if the current point's Longitude falls between the Longitudes of the edge (i, j)
                if ((poly[i].Lon < currentLon && poly[j].Lon >= currentLon) ||
                    (poly[j].Lon < currentLon && poly[i].Lon >= currentLon))
                {
                    // Calculate the Latitude of the intersection point on the edge.
                    if (poly[i].Lat + (currentLon - poly[i].Lon) /
                        (poly[j].Lon - poly[i].Lon) *
                        (poly[j].Lat - poly[i].Lat) < currentLat)
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